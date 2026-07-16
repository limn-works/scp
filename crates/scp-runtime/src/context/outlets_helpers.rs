//! Outlet helpers -- actor-shape signatures
//! (ADR-049 Phase 2A.4 + Phase 2A finalization, `outlet` domain).
//!
//! # Purpose
//!
//! This module hosts outlet-domain helpers that actor handlers call with
//! actor-owned state (`&mut PerContextState`). Two surfaces live here:
//!
//! 1. The hard-rate-limit consume / refund helpers
//!    ([`try_consume_hard_rate_limit`], [`refund_hard_rate_limit`]).
//! 2. The economy-pipeline split for outlet invocation
//!    ([`reserve_outlet_economy`], [`settle_outlet_economy_capture`],
//!    [`rollback_outlet_economy`]) plus the supervisor-side orchestrator
//!    [`invoke_outlet_with_economy`].
//!
//! # The `invoke_outlet_with_economy` actor split (Phase 2A finalization)
//!
//! The legacy `invoke_outlet_with_economy` ran the entire economy pipeline
//! under the `contexts` `DashMap` mutex (Phase 1 reserve), dropped the
//! lock, ran the executor off-lock (Phase 2), then re-locked for
//! post-invocation bookkeeping (Phase 3). ADR-049 deletes the `DashMap`,
//! so per-context state now lives ONLY inside the per-context actor.
//!
//! The outlet executor is a non-`Send` generic `FnOnce` closure (FFI
//! bridges supply GIL-bound / JS-bound closures) that cannot cross the
//! actor mailbox. The economy bookkeeping, by contrast, is `Send` and
//! mutates owned [`PerContextState`]. The split therefore runs:
//!
//! - **Phase 1 (reserve)** — [`reserve_outlet_economy`] runs INSIDE the
//!   actor handler ([`OutletsCommand::ReserveOutletEconomy`]) on
//!   `&mut PerContextState`. It consumes the hard rate limit, records the
//!   velocity entry, runs the economy pre-check, deducts budget,
//!   authorizes the payment escrow, and returns a `Send`
//!   [`OutletEconomyReservation`] (context handle + role-state snapshot +
//!   the in-flight [`OutletEconomyTicket`]).
//! - **Phase 2 (execute)** — the supervisor-side orchestrator
//!   [`invoke_outlet_with_economy`] runs the non-`Send` executor through
//!   [`invoke_outlet_execute_and_validate`] BETWEEN the two mailbox
//!   round-trips. No lock is held; the actor is free to process other
//!   commands.
//! - **Phase 3 (settle)** — on executor success
//!   [`settle_outlet_economy_capture`] runs inside the actor
//!   ([`OutletsCommand::SettleOutletEconomy`]) to perform post-invocation
//!   bookkeeping + consequence enforcement + payment capture; on
//!   executor failure [`rollback_outlet_economy`] voids the escrow and
//!   reverses budget / velocity / rate-limit.
//!
//! Splitting reserve/execute/settle keeps state mutation actor-exclusive
//! (the actor processes one command at a time) while letting the
//! non-`Send` closure run on the supervisor — which is exactly the
//! off-lock-executor invariant the legacy lock-split protected, expressed
//! in the actor model.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::lifecycle::OutletInvokedEvent;
use scp_protocol::context::outlets::registry::OutletRegistry;
use scp_protocol::context::roles::ContextRoleState;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::economy::antispam::VelocityRollbackToken;
use scp_protocol::economy::policy::ObservableMetrics;
use scp_protocol::economy::types::{Amount, PaymentAdapterRef};
use scp_protocol::trust::CaveatKind;
use scp_protocol::trust::caveats::InvocationCaveats;

use crate::context::ContextHandle;
use crate::context::actor::deps::ActorDeps;
use crate::context::outlets::invoke::{
    self, InvocationError, InvokeExecuteOutcome, OutletEconomyContext, build_outlet_event,
    economy_pre_check, invoke_outlet_execute_and_validate, post_outlet_invocation_bookkeeping,
};
use crate::economy::adapter::PaymentReceipt;
use crate::economy::integration::PreparedAction;

// ---------------------------------------------------------------------------
// try_consume_hard_rate_limit (actor-handler entry point)
// ---------------------------------------------------------------------------

/// Async hard-rate-limit consume for a live context actor.
///
/// Returns `true` if a token was consumed and `false` when the sender is
/// over budget. Unknown-context pass-through remains in the supervisor
/// shim fallback; once a command reaches this helper, the context actor
/// already owns the target [`PerContextState`].
#[must_use]
pub fn try_consume_hard_rate_limit(
    mut view: crate::context::actor::class_s::ClassCMut<'_>,
    did: &DID,
    now_secs: u64,
) -> bool {
    view.governance_class_c_mut()
        .hard_rate_limit_mut()
        .try_consume(did, now_secs)
}

// ---------------------------------------------------------------------------
// refund_hard_rate_limit (actor-handler entry point)
// ---------------------------------------------------------------------------

/// Refund one hard-rate-limit token for a live context actor.
///
/// Unknown-context no-op behavior remains in the supervisor shim
/// fallback; the actor path only runs after mailbox lookup succeeds.
pub fn refund_hard_rate_limit(mut view: crate::context::actor::class_s::ClassCMut<'_>, did: &DID) {
    view.governance_class_c_mut()
        .hard_rate_limit_mut()
        .refund(did);
}

// ---------------------------------------------------------------------------
// ManagedOutletInvocationOutput
// ---------------------------------------------------------------------------

/// Result of a successful managed outlet invocation. Returned to the FFI
/// bridges by [`invoke_outlet_with_economy`].
#[derive(Debug)]
pub struct ManagedOutletInvocationOutput {
    /// Outlet output JSON.
    pub output: serde_json::Value,
    /// Event to append to the event log.
    pub event: OutletInvokedEvent,
    /// Consequences triggered by the invocation.
    pub consequences: Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
    /// Payment receipt when a payment adapter is configured.
    pub payment_receipt: Option<PaymentReceipt>,
}

// ---------------------------------------------------------------------------
// OutletEconomyTicket — the in-flight economy bookkeeping bundle
// ---------------------------------------------------------------------------

/// Phase-1 bookkeeping bundle for a outlet invocation in flight. Crosses
/// the actor mailbox inside a [`OutletEconomyReservation`]: produced by
/// [`reserve_outlet_economy`] (actor), carried through the executor
/// (supervisor), then consumed by [`settle_outlet_economy_capture`] /
/// [`rollback_outlet_economy`] (actor).
///
/// The `#[must_use]` + `Drop` debug-assert invariant catches any future
/// refactor that leaks an unbalanced budget deduction or velocity entry.
/// All fields are `Send` so the ticket can cross the mailbox boundary.
#[must_use = "OutletEconomyTicket must be committed or rolled back — dropping leaks budget, velocity, and escrow state"]
pub struct OutletEconomyTicket {
    actor_did: DID,
    deducted_cost: Option<Amount>,
    velocity_token: VelocityRollbackToken,
    escrow: Option<PreparedAction>,
    policy_for_capture: Option<scp_protocol::economy::types::EconomicPolicy>,
    metrics_for_capture: ObservableMetrics,
    needs_hard_rate_limit_refund: bool,
    consumed: bool,
}

impl std::fmt::Debug for OutletEconomyTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutletEconomyTicket")
            .field("actor_did", &self.actor_did)
            .field("deducted_cost", &self.deducted_cost)
            .field(
                "needs_hard_rate_limit_refund",
                &self.needs_hard_rate_limit_refund,
            )
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

impl Drop for OutletEconomyTicket {
    fn drop(&mut self) {
        if !self.consumed {
            tracing::error!(
                actor_did = %self.actor_did,
                cost = ?self.deducted_cost,
                "OutletEconomyTicket dropped without commit or rollback — budget, velocity, and escrow state may be inconsistent"
            );
            debug_assert!(
                false,
                "OutletEconomyTicket dropped without commit or rollback for actor {}",
                self.actor_did
            );
        }
    }
}

fn commit_outlet_economy_ticket(mut ticket: OutletEconomyTicket) -> Option<Amount> {
    ticket.consumed = true;
    ticket.needs_hard_rate_limit_refund = false;
    ticket.deducted_cost
}

impl OutletEconomyTicket {
    /// Test-only constructor for an escrow-free ticket carrying a budget
    /// deduction. Used by supervisor-level settle tests that cannot reach
    /// the private ticket fields. No payment escrow ⇒
    /// `void_external_and_consume` is a pure consume.
    #[cfg(any(test, feature = "testing"))]
    pub fn new_for_test_no_escrow(actor_did: DID) -> Self {
        let tracker = scp_protocol::economy::antispam::SenderVelocityTracker::new(60);
        let velocity_token = tracker.record_message(&actor_did, 0);
        Self {
            actor_did,
            deducted_cost: Some(Amount::new(20)),
            velocity_token,
            escrow: None,
            policy_for_capture: None,
            metrics_for_capture: ObservableMetrics::default(),
            needs_hard_rate_limit_refund: true,
            consumed: false,
        }
    }

    /// Test-only constructor for an escrow-BEARING ticket carrying a budget
    /// deduction and a captured policy, so the capture path
    /// ([`settle_outlet_economy_capture`]) actually runs payment capture against a
    /// supplied adapter. Used by the RED-CS3 outlet-settle fail-closed test, which
    /// pairs this with a failing-capture adapter to exercise the
    /// payment-capture-failure early-return path.
    #[cfg(any(test, feature = "testing"))]
    pub fn new_for_test_with_escrow(
        actor_did: DID,
        escrow: PreparedAction,
        policy: scp_protocol::economy::types::EconomicPolicy,
    ) -> Self {
        let tracker = scp_protocol::economy::antispam::SenderVelocityTracker::new(60);
        let velocity_token = tracker.record_message(&actor_did, 0);
        Self {
            actor_did,
            deducted_cost: Some(Amount::new(50)),
            velocity_token,
            escrow: Some(escrow),
            policy_for_capture: Some(policy),
            metrics_for_capture: ObservableMetrics::default(),
            needs_hard_rate_limit_refund: true,
            consumed: false,
        }
    }

    /// Reverse the EXTERNAL side of a reservation when the owning actor
    /// is unreachable (despawned / replaced) and the per-context settle
    /// can therefore never run.
    ///
    /// Voids any payment-escrow hold via the supplied adapter and marks
    /// the ticket consumed so its `Drop` invariant does not fire. The
    /// internal budget / velocity / hard-rate-limit state lived in the
    /// (now gone) actor's `PerContextState` and was dropped with it, so
    /// there is nothing context-local left to refund — voiding the
    /// external escrow is the only reversal still possible and required
    /// (otherwise the external payment hold leaks). Idempotent: a ticket
    /// with no escrow simply consumes.
    pub async fn void_external_and_consume(
        mut self,
        payment_adapter: Option<&Arc<dyn crate::economy::adapter::PaymentAdapterDyn>>,
    ) {
        if let (Some(adapter), Some(prepared)) = (payment_adapter, self.escrow.as_ref()) {
            invoke::void_outlet_escrow(adapter.as_ref(), prepared).await;
        }
        // The context-local budget/velocity/rate-limit bookkeeping is
        // gone with the actor; mark consumed so the unbalanced-ticket
        // Drop guard does not fire.
        self.consumed = true;
        self.needs_hard_rate_limit_refund = false;
    }

    /// Synchronous last-resort consume for a sync, deps-less reply path
    /// (the [`reply_outlets_not_registered`] backstop) that cannot `.await`
    /// to void the escrow. Marks the ticket consumed so its Drop balance
    /// guard does not fire, and logs at ERROR if an external escrow hold
    /// is being abandoned without a void. This path is unreachable for
    /// `SettleOutletEconomy` through `dispatch_outlets_command` (which voids
    /// the escrow async before reaching the sync reply); it exists only
    /// as defense-in-depth so no future caller can resurrect the
    /// ticket-drop panic.
    ///
    /// [`reply_outlets_not_registered`]: crate::context::supervisor::Supervisor
    pub fn consume_abandoning_escrow(mut self) {
        if self.escrow.is_some() {
            tracing::error!(
                actor_did = %self.actor_did,
                "outlet-economy ticket consumed on a sync no-actor reply path that cannot void \
                 payment escrow — an external payment hold may leak. This backstop should be \
                 unreachable; the async settle path voids escrow first."
            );
        }
        self.consumed = true;
        self.needs_hard_rate_limit_refund = false;
    }

    /// Hold the ticket's external escrow RESERVED for operator repair on a
    /// cross-context-saga `NeedsRepair` divergence (spec §6.2.4 "`NeedsRepair`
    /// reservation semantics"). Unlike [`Self::void_external_and_consume`], this
    /// DELIBERATELY does NOT void the payment-escrow hold: the operation may have
    /// partially committed (the target executed and charged while the caller's
    /// settle did not land), so auto-voiding would be a free-execution exploit.
    /// The escrow stays held; the signed `CrossContextDivergenceMarker` plus
    /// operator repair settles it later (reconciling which side committed).
    ///
    /// This only marks the supervisor-side carrier ticket consumed so its
    /// unbalanced-drop guard does not fire — the external payment-escrow hold
    /// itself is untouched and remains active until operator repair settles it.
    /// The hard-rate-limit refund flag is cleared (the at-initiation budget
    /// consumption is NOT refunded on any non-`Committed` terminal, including
    /// `NeedsRepair` — spec §6.2.4 "Initiation consumes budget").
    pub fn hold_external_for_repair(mut self) {
        if self.escrow.is_some() {
            tracing::error!(
                actor_did = %self.actor_did,
                "cross-context saga NeedsRepair — external payment escrow held RESERVED for \
                 operator repair (NOT voided; the operation may have partially committed)"
            );
        }
        // Mark consumed so the supervisor-side carrier's unbalanced-drop guard
        // does not fire; the external hold is intentionally left in place.
        self.consumed = true;
        // No hard-rate-limit refund: initiation consumes budget, no terminal
        // refunds it (anti-griefing, §6.2.4).
        self.needs_hard_rate_limit_refund = false;
    }

    /// Project this in-flight ticket onto a durable, serde-safe
    /// [`CallerReservationRecord`] (spec §6.2.4) so a cross-context saga's
    /// caller-side Prepare-A reservation can be reversed after an actor crash
    /// WITHOUT the volatile RAII carrier (which dies with the crash).
    ///
    /// Reads — does NOT consume — the reversal-relevant fields: the budget
    /// delta, the hard-rate-limit refund flag, the external escrow
    /// authorization handle (the serde-safe
    /// [`PaymentAuthorization`](crate::economy::adapter::PaymentAuthorization)
    /// inside the non-serde [`PreparedAction`]), and the velocity-entry
    /// timestamp. The non-durable [`VelocityRollbackToken`] is intentionally
    /// dropped — a restored tracker re-synthesizes sequence numbers, so the
    /// durable reversal removes the velocity entry by TIMESTAMP via
    /// [`SenderVelocityTracker::rollback_one_at`](scp_protocol::economy::antispam::SenderVelocityTracker::rollback_one_at)
    /// instead. The ticket remains live and authoritative for the in-process
    /// (carrier) reversal path; this record is the crash-only fallback.
    pub(crate) fn to_caller_reservation_record(
        &self,
        recorded_at_secs: u64,
    ) -> crate::context::supervisor::saga_prepared_state::CallerReservationRecord {
        crate::context::supervisor::saga_prepared_state::CallerReservationRecord {
            actor_did: self.actor_did.clone(),
            deducted_cost: self.deducted_cost,
            needs_hard_rate_limit_refund: self.needs_hard_rate_limit_refund,
            recorded_at_secs,
            escrow_authorization: self
                .escrow
                .as_ref()
                .and_then(|prepared| prepared.envelope.authorization.clone()),
        }
    }
}

/// Reverse a cross-context saga's caller-side Prepare-A reservation from its
/// durable [`CallerReservationRecord`] (spec §6.2.4 "Reservation release on
/// every terminal path"), used EXCLUSIVELY by the crash-recovery abort path
/// (`Abort { None }`) where the in-memory RAII carrier died with the crash.
/// (The LIVE `Abort { Some }` and Commit-A paths reverse via the carrier
/// through [`rollback_outlet_economy_generation_checked`], NOT this function — so
/// this is the crash-recovery-only path and has exactly one production caller.)
///
/// Reverses the local budget / velocity / hard-rate-limit AND voids the
/// external escrow UNCONDITIONALLY — it does NOT gate on `state.generation`. On
/// the crash-recovery path the record AND the deductions it reverses are
/// rehydrated from ONE consistent Class-S snapshot into the SAME context's
/// restored state (`restore_context`), and the restored actor is routed by
/// `context_id` to the correct caller context (`record.actor_did` keys the very
/// trackers being reversed). A spawn-generation comparison here is therefore a
/// FALSE mismatch: every spawn — including a crash-recovery respawn — stamps a
/// fresh monotonic `state.generation` via `spawn_generation.fetch_add(1) + 1`
/// (resetting to 0 on a fresh process), while the restored record carries the
/// PRE-CRASH generation, so `record.generation != state.generation` ALWAYS
/// holds post-restart. Gating the refund on it would SKIP the local reversal on
/// every real restart and leave the caller durably over-charged on
/// budget / velocity / hard-rate-limit (the matching deductions are rehydrated
/// from the same snapshot) — exactly the over-charge this record exists to
/// close.
///
/// The confused-deputy concern the generation check addresses — a DIFFERENT
/// instance replacing the state between reserve and settle — belongs to the
/// LIVE reserve→settle race, which the carrier path
/// ([`rollback_outlet_economy_generation_checked`]) handles. It does not apply
/// here: there is no "replaced instance" on the crash path, only the same
/// context's state restored from its own consistent snapshot. Routing by
/// `context_id` and keying every reversal by `record.actor_did` is what
/// guarantees this writes only this actor's OWNED bookkeeping.
///
/// Always returns `true` (a present record on this path always drives a local
/// reversal); the caller folds that into its Class-S fail-closed persist
/// decision exactly as it does for a carrier rollback.
pub async fn reverse_caller_reservation_record(
    mut view: crate::context::actor::class_s::ClassCMut<'_>,
    deps: &ActorDeps,
    record: &crate::context::supervisor::saga_prepared_state::CallerReservationRecord,
) -> bool {
    // External escrow void is always safe (and required to avoid a leak): the
    // payment hold authorized at Prepare-A is real and external to any actor
    // instance. MUST be idempotent across a recovery re-drive — a persist
    // failure after this void leaves the record durable, so the next recovery
    // sweep voids the SAME `PaymentAuthorization` again (the same assumption
    // the carrier's `void_external_and_consume` already relies on).
    if let (Some(adapter), Some(auth)) = (
        deps.payment_adapter.as_ref(),
        record.escrow_authorization.as_ref(),
    ) && let Err(e) = adapter.void_dyn(auth).await
    {
        tracing::warn!(
            actor_did = %record.actor_did,
            "failed to void caller cross-context saga payment escrow on crash-recovery abort: {e}"
        );
    }

    // Reverse this restored actor's OWNED economy bookkeeping (Class-C governance
    // economy fields, reached through the field-granular `GovernanceClassCMut`
    // view — this helper cannot touch Class-S). Keyed by `record.actor_did`;
    // routing already guarantees this is the right context's restored state, so
    // there is no instance to confuse. No spawn-generation gate (see the
    // doc-comment): a fresh respawn-stamped generation never matches the
    // pre-crash record, so gating would wrongly skip every real crash-recovery
    // refund and durably over-charge the caller.
    let gov = view.governance_class_c_mut();
    gov.velocity_tracker_mut()
        .rollback_one_at(&record.actor_did, record.recorded_at_secs);
    if let Some(cost) = record.deducted_cost {
        gov.budget_tracker_mut()
            .reverse_spend(&record.actor_did, cost);
    }
    if record.needs_hard_rate_limit_refund {
        gov.hard_rate_limit_mut().refund(&record.actor_did);
    }
    true
}

// ---------------------------------------------------------------------------
// OutletEconomyReservation — the Send payload that crosses the mailbox
// ---------------------------------------------------------------------------

/// The `Send` output of the Phase-1 economy reserve. Produced by
/// [`reserve_outlet_economy`] inside the actor, carried by the supervisor
/// orchestrator across the non-`Send` executor, and handed back into the
/// actor for Phase 3 settle.
///
/// Carries the context handle + role-state snapshot (the executor's
/// off-lock inputs) and the in-flight [`OutletEconomyTicket`].
#[must_use = "a OutletEconomyReservation must be settled (capture) or rolled back — dropping leaks the held ticket"]
pub struct OutletEconomyReservation {
    /// Context handle snapshot — the executor reads lifecycle state and
    /// the supervisor passes it to [`invoke_outlet_execute_and_validate`].
    pub handle: ContextHandle,
    /// Role-state snapshot for the capability re-check inside the
    /// off-lock executor path.
    pub role_state: ContextRoleState,
    /// Spawn-generation of the actor instance this reservation was made
    /// against (`PerContextState::generation`). The Phase-3 settle
    /// rejects if the live actor's generation no longer matches — the
    /// actor was despawned and a new instance respawned for the same
    /// `context_id` between reserve and settle, so capturing/refunding
    /// against the new instance's owned state would be a confused-deputy
    /// write to the WRONG context instance.
    pub generation: u64,
    /// In-flight economy bookkeeping carried through the executor.
    pub ticket: OutletEconomyTicket,
}

impl std::fmt::Debug for OutletEconomyReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutletEconomyReservation")
            .field("ticket", &self.ticket)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// StreamEconomyReservation — the Send payload for the streaming open reserve
// ---------------------------------------------------------------------------

/// The `Send` output of the streaming open reserve
/// ([`reserve_outlet_stream_economy`]). Mirrors [`OutletEconomyReservation`]
/// for the streaming-native invocation path: produced inside the per-context
/// actor on owned Class-S state, carried by the supervisor orchestrator across
/// the non-`Send` off-mailbox pump, and consumed by the close-time settlement
/// (a later sub-chunk).
///
/// Unlike the unary reservation this carries NO in-flight
/// [`OutletEconomyTicket`]: the streaming path holds its economic reservation
/// as a debited `reserved_escrow` against the invoker's budget (refunded, net
/// of billed chunks, at stream close). The `economic_policy` is snapshotted at
/// acceptance so close-time settlement can capture the §19.15.5
/// `PaymentReceipt` for rendered service even if the context is torn down
/// mid-stream.
///
/// The per-sender MLS send-sequence (`base_sequence`) is deliberately NOT
/// carried here: it is allocated at the point of consumption on the send path
/// (allocate-at-consumption), never at open. A rollback-in-place of a
/// pre-allocated sequence across the off-mailbox pump window would corrupt a
/// DIFFERENT message's sequence — the actor's LIFO
/// [`rollback_sequence_number`](scp_protocol::context::membership::MembershipState::rollback_sequence_number)
/// `saturating_sub` is not request-scoped, and the off-mailbox bridge cannot
/// reach the actor's `PerContextState` `send_tracker` under ADR-049 isolation —
/// so the allocation is deferred to consumption. The cross-context send path
/// fills this hole (SCP-OUT-044) with a task-scoped `SendSequenceTracker` +
/// ADR-049 §8 `SequenceReservation` guard in `forward_frame` (which stamps the
/// anchor onto a
/// [`ForwardedStreamFrame`](crate::context::outlets::invoke::ForwardedStreamFrame));
/// see `run_cross_context_bridge`.
#[must_use = "a StreamEconomyReservation debits open-time escrow and must be settled or reversed at stream close — dropping leaks the held reservation"]
pub struct StreamEconomyReservation {
    /// Context handle snapshot — the off-mailbox pump reads lifecycle state
    /// and the supervisor threads it into the executor.
    pub handle: ContextHandle,
    /// Role-state snapshot for the capability re-check inside the off-mailbox
    /// pump path.
    pub role_state: ContextRoleState,
    /// Spawn-generation of the actor instance this reservation was made
    /// against (`PerContextState::generation`). Close-time settlement rejects
    /// (drops) if the live actor's generation no longer matches — the actor
    /// was despawned and a new instance respawned for the same `context_id`
    /// between reserve and settle, so refunding/capturing against the new
    /// instance's owned state would be a confused-deputy write to the WRONG
    /// context instance.
    pub generation: u64,
    /// The §5.4.5 open-time escrow HOLD debited against the invoker's budget:
    /// `cost_per_chunk × estimated_chunk_count` (`Amount(0)` for Query /
    /// zero-cost outlets). The unspent portion is refunded at stream close.
    pub reserved_escrow: Amount,
    /// The §5.4.5 MED-HIGH economic policy snapshot at acceptance, so
    /// close-time settlement can capture the receipt for rendered service even
    /// if the context is torn down mid-stream. `None` when the context has no
    /// economic policy.
    pub economic_policy: Option<scp_protocol::economy::types::EconomicPolicy>,
}

impl std::fmt::Debug for StreamEconomyReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamEconomyReservation")
            .field("generation", &self.generation)
            .field("reserved_escrow", &self.reserved_escrow)
            .finish_non_exhaustive()
    }
}

/// §7.3.8 fail-closed coupling of the validated-narrowed effective invocation
/// caveats to the revocation CID of the delegation that carried them.
///
/// The counter-bearing consume ([`consume_caveat_counters`]) needs BOTH the
/// caveat set (to know which caps to enforce) AND the `ucan_cid` (the
/// per-delegation counter key). Bundling them into one value makes "caveats
/// present ⟹ cid present" a COMPILE-TIME invariant rather than a three-bridge
/// convention: a caveat set for which
/// [`InvocationCaveats::has_counter_bearing_caveat`] is `true` can never reach
/// the counter gate without its counter key, so the fail-closed contract on
/// that method cannot be silently skipped by a `(Some(caveats), None)` pair.
///
/// Minted at the FFI bridge from the ONE validated invocation UCAN: the
/// `caveats` come from that token's `nb` (via `TokenNbCaveatResolver`), the
/// `ucan_cid` from `compute_revocation_cid` over the same token — the two are
/// derived together, from the same token, or the whole binding is `None`.
#[derive(Debug, Clone)]
pub struct InvocationCaveatBinding {
    /// The validated-narrowed effective invocation caveats (the leaf `nb`).
    pub caveats: InvocationCaveats,
    /// Revocation CID of the invocation UCAN — the per-delegation key for the
    /// owned Class-S caveat counters.
    pub ucan_cid: String,
}

// ---------------------------------------------------------------------------
// Phase 1: reserve_outlet_economy (actor handler entry point)
// ---------------------------------------------------------------------------

/// Phase 1 of the outlet economy pipeline, run inside the per-context
/// actor on owned state. Consumes the hard rate limit, records the
/// velocity entry, runs the economy pre-check, deducts budget, validates
/// the spending UCAN, and authorizes the payment escrow.
///
/// On any failure branch the hard-rate-limit token is refunded inline
/// (and velocity rolled back / budget reversed as applicable) so a
/// rejected reservation leaves observable state unchanged. On success
/// returns a `Send` [`OutletEconomyReservation`] the supervisor carries
/// across the executor.
///
/// # Errors
///
/// Propagates [`ContextError`] for rate-limit, budget, spending-UCAN, and
/// escrow-authorization failures.
/// # §7.3.8 value-caveat enforcement
///
/// When `caveat_binding` is `Some` (the VALIDATED INVOCATION UCAN — the
/// token granting `outlet_call:*` / `outlet_query:*` — carried a
/// validated-narrowed `nb` caveat set, resolved by the FFI bridge via
/// `TokenNbCaveatResolver` at its `validate_outlet_invocation_ucan` site and
/// threaded here as an internal runtime param, bundled with the delegation's
/// `ucan_cid` so "caveats present ⟹ cid present" holds by construction; NOT
/// sourced from `spending_ucan`, a separate §19.5 economy token), this function
/// runs the two-stage §7.3.8 gate:
///
/// 1. [`InvocationCaveats::check_invocation_local`] — the SYNCHRONOUS stateless
///    checks (`input_schema` / `amount_max_per_call` / `allowed_adapters` /
///    `allowed_target_dids`). Runs FIRST, so a bad schema / adapter / target /
///    per-call amount rejects BEFORE any Class-S consume — velocity and the
///    hard rate limit are refunded and no nonce / budget / counter capacity is
///    spent.
/// 2. [`consume_caveat_counters`] — the counter-bearing caps (`max_calls` /
///    `amount_max_cumulative` / `rate_window`). Consumed as a Class-S mutation
///    folded into the paid-path `commit_class_s_keep_compensating` (one persist
///    per invocation) or a dedicated `commit_class_s_keep` on the free path.
///    A consumed cap is KEPT on persist failure (ADR-049 §9) and KEPT across a
///    later executor failure (attempt-based, not success-based).
///
/// `negotiated_adapter` is derived here from `deps.payment_adapter` (the
/// adapter the paid path will use); `target_did` is `None` for this single-shot
/// same-context slice (cross-context target threading is a later slice).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn reserve_outlet_economy(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    invoker_did: &DID,
    spending_ucan: Option<&UcanToken>,
    caveat_binding: Option<&InvocationCaveatBinding>,
    input: &serde_json::Value,
    now_secs: u64,
) -> Result<OutletEconomyReservation, ContextError> {
    // ADR-049 §9 Class-S cell seam. The spending-nonce consume + budget charge
    // + fail-closed persist on the PAID path are routed through
    // `commit_class_s_keep_compensating` below; the pre-persist bookkeeping that
    // runs regardless (hard rate limit, velocity, pre-check) is ALL Class-C, so
    // it is routed through the non-persisting `class_c_view()` (the run loop
    // coalesce-persists the bookkeeping mutations), with the view dropped before
    // the combinator call.
    //
    // The §19 economy pre-check needs `&mut budget_tracker` held SIMULTANEOUSLY
    // with `&velocity_tracker` (plus `&economic_policy` / `&consequence_rules` /
    // `&message_pricing`) — two-plus disjoint fields of the SAME governance
    // bucket. `GovernanceClassCMut::economy_pre_check_borrows()` destructures the
    // view into exactly those five disjoint `&mut`/`&` field references at once,
    // so the whole pre-check runs without re-borrowing the view between steps.
    // The borrows struct is dropped before the error arm's `velocity_tracker_mut`
    // rollback / `hard_rate_limit_mut` refund so those `&mut self` reborrows are
    // permitted (NLL).
    let event_log = &deps.event_log;
    let key_resolver = &deps.key_resolver;
    let clock = deps.clock.as_ref();
    let payment_adapter = deps.payment_adapter.clone();

    let handle;
    let role_state;
    let velocity_token;
    let metrics;
    let economic_policy;
    let action_cost;
    {
        let mut view = cell.class_c_view();

        handle = view.handle_mut().clone();
        role_state = view.role_state().clone();
        let member_count = u64::try_from(view.membership_class_c_mut().count()).unwrap_or(u64::MAX);

        let gov = view.governance_class_c_mut();

        // Hard rate limit — the Matrix Synapse–style defense-in-depth cap on
        // the outlet path. try_consume before any Phase-1 bookkeeping.
        if !gov.hard_rate_limit_mut().try_consume(invoker_did, now_secs) {
            return Err(ContextError::RateLimited {
                resource: "outlet_call".to_owned(),
                message: "hard rate limit exceeded for invoker".to_owned(),
                // Token-bucket hard limit: no exact refill instant to surface.
                retry_after_ms: None,
            });
        }

        velocity_token = gov
            .velocity_tracker_mut()
            .record_message(invoker_did, now_secs);

        let velocity = gov
            .velocity_tracker_mut()
            .get_velocity(invoker_did, now_secs);
        let aggregate = gov.velocity_tracker_mut().aggregate_velocity(now_secs);
        metrics = ObservableMetrics {
            sender_velocity: velocity,
            member_count,
            context_message_rate: aggregate,
            relay_queue_depth: 0,
            time_of_day: now_secs % 86400,
            storage_usage: 0,
        };

        // `economic_policy` is cloned out for the later escrow-authorization
        // `.await` (which holds no view borrow). The pre-check's own reads of
        // `economic_policy` / `consequence_rules` / `message_pricing` come from
        // `economy_pre_check_borrows()` below, so no separate clones are needed.
        economic_policy = gov.economic_policy_mut().clone();

        let (events_snapshot, convergent_now) =
            crate::context::governance_logic::event_log_entries_for_consequences(
                view.receive_buffer_mut(),
                context_id,
                now_secs,
                event_log.as_ref(),
            );

        let mut participation_cache: HashMap<
            String,
            scp_protocol::trust::participation::ParticipationRecord,
        > = HashMap::new();

        action_cost = {
            // `economy_pre_check_borrows()` hands back `&mut budget_tracker` held
            // simultaneously with `&velocity_tracker` / `&economic_policy` /
            // `&consequence_rules` / `&message_pricing` — the disjoint borrows the
            // pre-check needs at once. Scoped to this block so it drops before the
            // error arm's `velocity_tracker_mut` rollback (NLL).
            let pre_check_result = {
                let borrows = view.governance_class_c_mut().economy_pre_check_borrows();
                let economy = OutletEconomyContext {
                    economic_policy: borrows.economic_policy.as_ref(),
                    budget_tracker: borrows.budget_tracker,
                    spending_ucan,
                    context_id,
                    now: now_secs,
                    events: &events_snapshot,
                    convergent_now,
                    participation_cache: &mut participation_cache,
                    consequence_rules: borrows.consequence_rules,
                    payment_adapter: payment_adapter.clone(),
                    metrics: metrics.clone(),
                    velocity_tracker: Some(borrows.velocity_tracker),
                    message_pricing: borrows.message_pricing.as_ref(),
                };
                economy_pre_check(&economy, invoker_did)
            };

            match pre_check_result {
                Ok(cost) => cost,
                Err(err) => {
                    let gov = view.governance_class_c_mut();
                    gov.velocity_tracker_mut()
                        .rollback(invoker_did, velocity_token);
                    gov.hard_rate_limit_mut().refund(invoker_did);
                    return Err(invocation_error_to_context(err));
                }
            }
        };

        // The paid path requires a spending UCAN before any Class-S nonce work.
        // Validated here (outside the combinator) so the velocity/hard-rate
        // rollback for a missing UCAN runs without staging a Class-S mutation.
        if action_cost.0 > 0 && spending_ucan.is_none() {
            let gov = view.governance_class_c_mut();
            gov.velocity_tracker_mut()
                .rollback(invoker_did, velocity_token);
            gov.hard_rate_limit_mut().refund(invoker_did);
            return Err(ContextError::PermissionDenied(
                "SCP-ECON-12060: paid action requires spending UCAN".to_owned(),
            ));
        }

        // §7.3.8 SYNCHRONOUS caveat gate (stateless local checks). Runs HERE —
        // after `action_cost` is known but BEFORE any Class-S consume (spending
        // nonce, budget, or counter capacity) — so a bad `input_schema` /
        // `amount_max_per_call` / `allowed_adapters` / `allowed_target_dids`
        // rejects the invocation without spending anything. On rejection the
        // velocity tick + hard-rate token consumed above are refunded inline
        // (mirroring the missing-spending-UCAN arm), and NO counter is touched.
        //
        // `negotiated_adapter` is the adapter the paid path would use
        // (`deps.payment_adapter.adapter_id()`); `target_did` is `None` for this
        // single-shot same-context slice — a token whose `allowed_target_dids`
        // is populated therefore cannot authorize a same-context call, which is
        // the correct fail-closed behaviour (cross-context targets are a later
        // slice).
        if let Some(binding) = caveat_binding {
            let caveats = &binding.caveats;
            let negotiated_adapter: Option<PaymentAdapterRef> =
                payment_adapter.as_ref().map(|a| a.adapter_id().to_owned());
            if let Err(err) = caveats.check_invocation_local(
                input,
                action_cost,
                negotiated_adapter.as_ref(),
                None,
            ) {
                let gov = view.governance_class_c_mut();
                gov.velocity_tracker_mut()
                    .rollback(invoker_did, velocity_token);
                gov.hard_rate_limit_mut().refund(invoker_did);
                return Err(check_invocation_error_to_context(&err));
            }
        }
        // `view` is dropped here, releasing `cell` for the combinator call.
    }

    // PAID path (`action_cost.0 > 0`, spending UCAN present): the spending-UCAN
    // replay validation, budget charge, and spending-nonce consume are Class-S
    // (+ Class-C) mutations that MUST be durably persisted fail-closed BEFORE
    // the reservation is acknowledged — otherwise an actor crash in the ≤50ms
    // coalesce window would roll the nonce consume back, letting the same
    // spending UCAN nonce be replayed after the caller already saw the spend
    // succeed. `commit_class_s_keep_compensating` performs that fail-closed
    // persist: `f` consumes the nonce (Class-S — KEPT on persist failure, since
    // un-consuming re-opens the replay window) and charges the in-memory budget
    // (Class-C); on persist failure `on_persist_failure` REVERSES the Class-C
    // budget reservation and the velocity tick (which did not durably land),
    // while the consumed nonce is intentionally retained. The hard-rate-limit
    // refund runs in the outer error arm below — `ClassCMut` holds no reference
    // to the `hard_rate_limit` token bucket, so the persist-failure refund
    // cannot be expressed through that view.
    //
    // FREE path (`action_cost.0 == 0`): no spending UCAN nonce is consumed and
    // no budget is charged, so — exactly as before — NO fail-closed persist runs
    // (the velocity tick / hard-rate consume ride the ordinary best-effort
    // persist elsewhere); the combinator is skipped entirely.
    let deducted_cost = if action_cost.0 > 0 {
        let combinator_result = cell
            .commit_class_s_keep_compensating(
                deps,
                context_id,
                |mut view| {
                    let state = view.rest_mut();
                    // Spending UCAN replay validation (Class-S nonce dedup record).
                    let spending = spending_ucan.ok_or_else(|| {
                        ContextError::PermissionDenied(
                            "SCP-ECON-12060: paid action requires spending UCAN".to_owned(),
                        )
                    })?;
                    if let Err(err) =
                        crate::context::economy_logic::validate_spending_ucan_or_error(
                            spending,
                            invoker_did,
                            context_id,
                            &mut state.governance.class_s.spending_nonce_tracker,
                            &state.governance.revoked_spending_ucan_cids,
                            key_resolver,
                            clock,
                        )
                    {
                        state
                            .governance
                            .velocity_tracker
                            .rollback(invoker_did, velocity_token);
                        // hard rate limit is refunded once in the outer error arm
                        // (it is not reachable through the `ClassCMut` compensation
                        // view, and a second refund would over-credit the bucket).
                        return Err(err);
                    }

                    // Budget charge (Class-C). Reversed by `on_persist_failure`
                    // if the persist does not land.
                    if state
                        .governance
                        .budget_tracker
                        .record_spend(invoker_did, action_cost)
                        .is_err()
                    {
                        let remaining =
                            state.governance.budget_tracker.remaining(invoker_did).0;
                        state
                            .governance
                            .velocity_tracker
                            .rollback(invoker_did, velocity_token);
                        // hard rate limit refunded once in the outer error arm.
                        return Err(invocation_error_to_context(
                            InvocationError::BudgetExceeded {
                                did: invoker_did.to_string(),
                                cost: action_cost.0,
                                remaining,
                            },
                        ));
                    }
                    let deducted_cost = Some(action_cost);

                    // Spending-nonce consume (Class-S). On commit failure, roll
                    // the just-charged budget + velocity back inline and reject
                    // before any persist runs (hard rate limit refunded once in
                    // the outer error arm).
                    if let Err(e) =
                        scp_protocol::crypto::ucan::spending::commit_spending_ucan_nonce(
                            spending,
                            &mut state.governance.class_s.spending_nonce_tracker,
                        )
                    {
                        if let Some(cost) = deducted_cost {
                            state
                                .governance
                                .budget_tracker
                                .reverse_spend(invoker_did, cost);
                        }
                        state
                            .governance
                            .velocity_tracker
                            .rollback(invoker_did, velocity_token);
                        return Err(ContextError::PermissionDenied(format!(
                            "SCP-ECON-12066: nonce commit failed after budget acceptance: {e}"
                        )));
                    }

                    // §7.3.8 counter-bearing caveat consume (Class-S), folded
                    // into THIS combinator so the paid path persists exactly
                    // once. It is the LAST mutation in the closure: on a
                    // `CounterExhausted` reject the just-charged budget + velocity
                    // are rolled back inline (the spending nonce stays consumed —
                    // un-consuming it re-opens the replay window; a caller who
                    // trips their own cap after presenting a valid spending UCAN
                    // burns that nonce, an acceptable self-inflicted cost). The
                    // consume is all-or-nothing across the three kinds, so a
                    // partial increment never persists. On success the record
                    // rides the fail-closed persist below and is KEPT on persist
                    // failure (a consumed cap must never un-consume).
                    if let Some(binding) = caveat_binding
                        && binding.caveats.has_counter_bearing_caveat()
                        && let Err(err) = consume_caveat_counters(
                            &mut state.class_s.caveat_counters,
                            &binding.ucan_cid,
                            &binding.caveats,
                            action_cost,
                            now_secs,
                        )
                    {
                        if let Some(cost) = deducted_cost {
                            state
                                .governance
                                .budget_tracker
                                .reverse_spend(invoker_did, cost);
                        }
                        state
                            .governance
                            .velocity_tracker
                            .rollback(invoker_did, velocity_token);
                        return Err(err);
                    }

                    // `value` = the deducted cost; `external` = the handle the
                    // persist-failure reversal needs to reverse the Class-C
                    // budget reservation.
                    Ok((deducted_cost, deducted_cost))
                },
                // KEEP-direction Class-S (nonce stays consumed). Reverse the
                // Class-C budget reservation + velocity tick the failed persist
                // did not make durable. `view` is a `ClassCMut` — it cannot
                // re-touch Class-S (and cannot reach `hard_rate_limit`, which is
                // refunded in the outer arm below).
                async |charged_cost: Option<Amount>, mut view, _deps| {
                    let gov = view.governance_class_c_mut();
                    if let Some(cost) = charged_cost {
                        gov.budget_tracker_mut().reverse_spend(invoker_did, cost);
                    }
                    gov.velocity_tracker_mut()
                        .rollback(invoker_did, velocity_token);
                },
            )
            .await;

        match combinator_result {
            Ok(deducted_cost) => deducted_cost,
            Err(err) => {
                // Single hard-rate-limit refund site for every combinator error
                // path (`f`-reject and persist-failure alike). `f` and
                // `on_persist_failure` perform the velocity / budget reversals they
                // can reach; the hard rate limit is NOT reachable through the
                // `ClassCMut` compensation view, so its refund runs here — exactly
                // once, matching the original inline single refund (a second refund
                // would over-credit the token bucket). The refund is a Class-C
                // governance mutation routed through the non-persisting
                // `class_c_view()` (the reserve path's persist already happened in
                // the combinator above; this error arm injects no extra persist).
                cell.class_c_view()
                    .governance_class_c_mut()
                    .hard_rate_limit_mut()
                    .refund(invoker_did);
                return Err(err);
            }
        }
    } else {
        // FREE path (`action_cost == 0`, no spending nonce / budget). A free
        // outlet may still carry a counter-bearing caveat (`max_calls` /
        // `rate_window`, or an `amount_max_cumulative` that consumes 0 but still
        // asserts its cap), so the counter consume gets its OWN dedicated
        // fail-closed `commit_class_s_keep` — KEEP on persist failure (a consumed
        // cap must never un-consume). On reject / persist failure the velocity
        // tick + hard-rate token are refunded (they were consumed in the Class-C
        // pre-block above and, on this path, would otherwise ride only the
        // best-effort coalesce persist).
        if let Some(binding) = caveat_binding
            && binding.caveats.has_counter_bearing_caveat()
        {
            let consume_result = cell
                .commit_class_s_keep(deps, context_id, |mut view| {
                    let state = view.rest_mut();
                    consume_caveat_counters(
                        &mut state.class_s.caveat_counters,
                        &binding.ucan_cid,
                        &binding.caveats,
                        action_cost,
                        now_secs,
                    )
                })
                .await;
            if let Err(err) = consume_result {
                let mut view = cell.class_c_view();
                let gov = view.governance_class_c_mut();
                gov.velocity_tracker_mut()
                    .rollback(invoker_did, velocity_token);
                gov.hard_rate_limit_mut().refund(invoker_did);
                return Err(err);
            }
        }
        None
    };

    // The escrow authorization is an EXTERNAL `.await` that touches no actor
    // state; do it without holding a state borrow. Only the failure arm mutates
    // Class-C governance economy, routed through the non-persisting
    // `class_c_view()` (the paid-path persist already ran in the combinator
    // above; this reserve error arm injects no extra persist).
    let escrow = match (economic_policy.as_ref(), payment_adapter.as_ref()) {
        (Some(policy), Some(adapter)) => {
            match invoke::authorize_outlet_payment(
                adapter.as_ref(),
                policy,
                context_id,
                invoker_did,
                &metrics,
            )
            .await
            {
                Ok(prepared) => prepared,
                Err(auth_err) => {
                    let mut view = cell.class_c_view();
                    let gov = view.governance_class_c_mut();
                    if let Some(cost) = deducted_cost {
                        gov.budget_tracker_mut().reverse_spend(invoker_did, cost);
                    }
                    gov.velocity_tracker_mut()
                        .rollback(invoker_did, velocity_token);
                    gov.hard_rate_limit_mut().refund(invoker_did);
                    return Err(invocation_error_to_context(auth_err));
                }
            }
        }
        _ => None,
    };

    let ticket = OutletEconomyTicket {
        actor_did: invoker_did.clone(),
        deducted_cost,
        velocity_token,
        escrow,
        policy_for_capture: economic_policy,
        metrics_for_capture: metrics,
        needs_hard_rate_limit_refund: true,
        consumed: false,
    };

    // `generation` is a Class-C structural field read through the cell `Deref`.
    Ok(OutletEconomyReservation {
        handle,
        role_state,
        generation: cell.generation,
        ticket,
    })
}

// ---------------------------------------------------------------------------
// reserve_outlet_stream_economy (streaming open — actor handler entry point)
// ---------------------------------------------------------------------------

/// Streaming open-time economy reserve, run inside the per-context actor on
/// owned Class-S state — the streaming-native counterpart of
/// [`reserve_outlet_economy`].
///
/// Mirrors the unary reserve's shared prelude (handle + role-state snapshot,
/// hard-rate-limit consume, velocity record, economic-policy snapshot) and
/// then runs the streaming-specific open-time gates:
///
/// 1. **Membership gate** — the invoker must be on the §9.8.5 membership
///    roster ([`MembershipState::contains`](scp_protocol::context::membership::MembershipState::contains));
///    a non-member has no per-sender stream state and is rejected. The
///    per-sender `base_sequence` is NOT allocated here — the send path
///    allocates it at the point of consumption (allocate-at-consumption),
///    because a rollback-in-place across the off-mailbox pump window would
///    corrupt a DIFFERENT message's sequence (the actor's LIFO
///    `saturating_sub` is not request-scoped, and the off-mailbox bridge
///    cannot reach the actor `send_tracker` under ADR-049 isolation). The
///    cross-context send path fills this hole (SCP-OUT-044) with a
///    task-scoped `SendSequenceTracker` in `forward_frame` /
///    `run_cross_context_bridge`.
/// 2. **Open-time escrow** — a faithful port of the reference
///    `outlet_stream_reserve_escrow`: `reserved = cost_per_chunk ×
///    estimated_chunk_count` (checked; overflow → `EscrowOverflow`), gated
///    against the invoker's live remaining budget AND-folded with the §19.5
///    `max_per_action` per-action ceiling, then DEBITED under a fail-closed
///    persist. `cost_per_chunk == 0` (Query / zero-cost) short-circuits to
///    `reserved = 0` with no debit and no balance consultation.
///
/// The §7.3.8 counter-bearing caveat reserve is NOT performed here — it stays
/// at the pump's open-time Step 5.5 (a later sub-chunk), preserving the R4
/// HIGH-2 ordering (counters are the LAST gate, after the pump permit).
///
/// On ANY failure branch after a consume the token is refunded / the mutation
/// rolled back inline: the hard-rate token is refunded exactly once (on the
/// early-return branches and in the single outer error arm around the
/// combinator), the velocity tick is rolled back on whichever branch consumed
/// it, and the budget debit is reversed by the persist-failure compensation —
/// so a rejected reservation leaves observable state unchanged. No sequence is
/// allocated here, so there is none to roll back.
///
/// # Errors
///
/// - [`ContextError::RateLimited`] — hard rate limit exceeded for the invoker.
/// - [`ContextError::PermissionDenied`] — the invoker is not a member of the
///   context (no per-sender stream state).
/// - An escrow-overflow / insufficient-funds [`ContextError`] — reusing the
///   [`OpenStreamRejection`](crate::context::outlets::dispatch::OpenStreamRejection)
///   `EscrowOverflow` / `InsufficientFunds` variants routed through
///   [`OpenStreamRejection::to_invocation_error`](crate::context::outlets::dispatch::OpenStreamRejection::to_invocation_error)
///   — `cost × count` overflowed, or the effective remaining budget is below
///   the reservation.
/// - [`ContextError::PersistenceFailed`] — the fail-closed escrow-debit persist
///   did not land (budget + velocity + sequence reversed by the compensation).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn reserve_outlet_stream_economy(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    invoker_did: &DID,
    cost_per_chunk: Amount,
    estimated_chunk_count: u32,
    max_per_action: Option<Amount>,
    now_secs: u64,
) -> Result<StreamEconomyReservation, ContextError> {
    use crate::context::outlets::dispatch::OpenStreamRejection;

    // --- Shared prelude (mirrors reserve_outlet_economy ~588-626): handle +
    // role-state snapshot, hard-rate consume, velocity record, economic-policy
    // snapshot. All Class-C, routed through the non-persisting `class_c_view()`
    // (the run loop coalesce-persists these bookkeeping mutations).
    let handle;
    let role_state;
    let velocity_token;
    let economic_policy;
    {
        let mut view = cell.class_c_view();
        handle = view.handle_mut().clone();
        role_state = view.role_state().clone();

        let gov = view.governance_class_c_mut();
        // Hard rate limit — the Matrix Synapse-style defense-in-depth cap.
        // try_consume before any streaming-open bookkeeping.
        if !gov.hard_rate_limit_mut().try_consume(invoker_did, now_secs) {
            return Err(ContextError::RateLimited {
                resource: "outlet_stream_open".to_owned(),
                message: "hard rate limit exceeded for invoker".to_owned(),
                // Token-bucket hard limit: no exact refill instant to surface.
                retry_after_ms: None,
            });
        }
        velocity_token = gov
            .velocity_tracker_mut()
            .record_message(invoker_did, now_secs);
        economic_policy = gov.economic_policy_mut().clone();
        // `view` dropped here.
    }

    // --- Membership gate (Class-C membership roster, §9.8.5). A non-member has
    // no per-sender stream state — reject (rolling back the velocity tick +
    // hard-rate token consumed above). The per-sender `base_sequence` is NOT
    // allocated here: the send path allocates it at the point of consumption
    // (allocate-at-consumption). Holding a pre-allocated sequence across the
    // off-mailbox pump window and rolling it back in place would corrupt a
    // DIFFERENT message's sequence — the actor's LIFO `saturating_sub` in
    // `rollback_sequence_number` is not request-scoped, and the off-mailbox
    // bridge cannot reach the actor `send_tracker` under ADR-049 isolation — so
    // the allocation is deferred to consumption. The cross-context send path
    // fills this hole (SCP-OUT-044): a task-scoped `SendSequenceTracker` +
    // ADR-049 §8 `SequenceReservation` in `forward_frame` /
    // `run_cross_context_bridge`.
    let invoker_did_str = invoker_did.to_string();
    if !cell
        .class_c_view()
        .membership_class_c_mut()
        .contains(&invoker_did_str)
    {
        let mut view = cell.class_c_view();
        let gov = view.governance_class_c_mut();
        gov.velocity_tracker_mut()
            .rollback(invoker_did, velocity_token);
        gov.hard_rate_limit_mut().refund(invoker_did);
        return Err(ContextError::PermissionDenied(format!(
            "SCP-OUTLET-6089: invoker {invoker_did} is not a member of context \
             '{context_id}' — cannot open a stream"
        )));
    }

    // --- Open-time escrow reserve (port of `outlet_stream_reserve_escrow`).
    let reserved_escrow = if cost_per_chunk.value() == 0 {
        // Zero-cost / Query: no debit, no balance consultation, no persist.
        Amount::new(0)
    } else {
        // Overflow is a PURE check on `cost × count` — done BEFORE any debit so
        // an overflow rejects without consulting or debiting the budget. On
        // overflow the velocity tick + hard-rate token consumed above are
        // rolled back (no sequence was allocated — see the membership gate).
        let Some(reserved) = cost_per_chunk.checked_mul(u64::from(estimated_chunk_count)) else {
            let mut view = cell.class_c_view();
            let gov = view.governance_class_c_mut();
            gov.velocity_tracker_mut()
                .rollback(invoker_did, velocity_token);
            gov.hard_rate_limit_mut().refund(invoker_did);
            return Err(invocation_error_to_context(
                OpenStreamRejection::EscrowOverflow.to_invocation_error(),
            ));
        };

        // Gate + DEBIT under a fail-closed persist. The actor processes commands
        // serially, so the check-and-debit is atomic without an external lock
        // (the two-concurrent-opens race the reference closed with `arc.lock()`
        // cannot occur on the mailbox). The budget debit is Class-C; on persist
        // failure the compensation reverses it (mirroring the unary paid path),
        // and the outer arm refunds the hard-rate token.
        let debit_result = cell
            .commit_class_s_keep_compensating(
                deps,
                context_id,
                |mut view| {
                    let state = view.rest_mut();
                    let remaining = state.governance.budget_tracker.remaining(invoker_did);
                    // §19.5 AND-composition: fold the per-action ceiling into the
                    // effective spendable balance when a cap is present.
                    let effective_remaining = max_per_action.map_or(remaining, |cap| {
                        Amount::new(remaining.value().min(cap.value()))
                    });
                    if reserved.value() > effective_remaining.value() {
                        // Insufficient funds: reject BEFORE the debit. Roll the
                        // velocity tick back inline (reachable through the owned
                        // state); the hard-rate token is refunded once in the
                        // outer arm. No sequence was allocated to roll back.
                        state
                            .governance
                            .velocity_tracker
                            .rollback(invoker_did, velocity_token);
                        return Err(invocation_error_to_context(
                            OpenStreamRejection::InsufficientFunds.to_invocation_error(),
                        ));
                    }
                    if state
                        .governance
                        .budget_tracker
                        .record_spend(invoker_did, reserved)
                        .is_err()
                    {
                        // Defensive: a `record_spend` reject (budget drained after
                        // the local comparison). The serial actor makes this
                        // unreachable, but fail closed — roll back the velocity
                        // tick inline (no sequence was allocated).
                        state
                            .governance
                            .velocity_tracker
                            .rollback(invoker_did, velocity_token);
                        return Err(invocation_error_to_context(
                            OpenStreamRejection::InsufficientFunds.to_invocation_error(),
                        ));
                    }
                    // `value` = the reserved hold returned to the caller;
                    // `external` = the same hold the persist-failure reversal
                    // needs to reverse the Class-C budget debit.
                    Ok((reserved, reserved))
                },
                // KEEP-direction (no Class-S mutation to restore). On persist
                // failure reverse the Class-C budget debit + velocity tick the
                // failed persist did not make durable (no sequence was
                // allocated). `view` is a `ClassCMut` — it cannot reach
                // `hard_rate_limit`, which is refunded in the outer arm below.
                async |reserved: Amount, mut view, _deps| {
                    let gov = view.governance_class_c_mut();
                    gov.budget_tracker_mut()
                        .reverse_spend(invoker_did, reserved);
                    gov.velocity_tracker_mut()
                        .rollback(invoker_did, velocity_token);
                },
            )
            .await;

        match debit_result {
            Ok(reserved) => reserved,
            Err(err) => {
                // Single hard-rate-limit refund site for every combinator error
                // path (`f`-reject and persist-failure alike): `f` and the
                // compensation reverse the velocity + budget they can reach; the
                // hard-rate token is refunded here exactly once (it is
                // not reachable through the compensation `ClassCMut` view). Routed
                // through the non-persisting `class_c_view()` — the reserve's
                // persist already ran in the combinator; this arm injects none.
                cell.class_c_view()
                    .governance_class_c_mut()
                    .hard_rate_limit_mut()
                    .refund(invoker_did);
                return Err(err);
            }
        }
    };

    // `generation` is a Class-C structural field read through the cell `Deref`.
    Ok(StreamEconomyReservation {
        handle,
        role_state,
        generation: cell.generation,
        reserved_escrow,
        economic_policy,
    })
}

/// §5.4.5 GRANT-time escrow top-up on actor-owned state — the mid-stream
/// counterpart of the escrow-debit block in [`reserve_outlet_stream_economy`].
///
/// Spec §5.4.5 "Credit-grant escrow top-up": each validly accepted
/// `OutletStreamCredit` grant on an Action outlet with `cost > 0` tops up the
/// stream's escrow by `cost_per_chunk × grant`, computed via `checked_mul`
/// (overflow → `EscrowOverflow`), rejecting with `InsufficientFunds` when the
/// invoker's available balance is below the top-up. This function performs
/// exactly that check-and-DEBIT against the invoker's
/// [`MemberBudgetTracker`](scp_protocol::economy::budget::MemberBudgetTracker),
/// returning the reserved hold the FFI bridge threads into
/// [`apply_credit_grant`](crate::context::outlets::dispatch::StreamSessionHandle::apply_credit_grant)
/// as `reserved_top_up`.
///
/// It DELIBERATELY runs NO hard-rate / velocity / membership gate — those are
/// admission-time concerns already paid at open; a grant is a mid-stream
/// top-up on an already-admitted stream. The §5.4.5:758 cumulative billable
/// ceiling (`min(credit_window, max_calls)`) is enforced separately by the
/// pump's `CreditTracker::max_billable`, so no quantity of grants can bill past
/// the invoker's caveat ceiling regardless of how much escrow is held.
///
/// # Money-conservation + crash-recovery
///
/// The debit is the ONLY authority for billing the granted chunks: the pump
/// bills at most `reserved_top_up / cost_per_chunk` further Data chunks against
/// this hold, and the unspent remainder is refunded at close by the same
/// settlement path that refunds the open-time hold. If the grant apply then
/// rejects, the caller MUST reverse this exact amount via
/// [`reverse_stream_grant_escrow`] so `billed + refund == reserved` holds across
/// open + every grant.
///
/// The debit is paired ATOMICALLY (same fail-closed commit) with a bump of the
/// durable crash-recovery record's
/// [`reserved_escrow`](crate::context::outlets::invoke::StreamReservationRecord::reserved_escrow)
/// keyed by `request_id`. Without this, a hard crash AFTER a grant would leave
/// [`reconcile_stream_reservations`] refunding only the OPEN-time hold (the
/// record still carries the open value) while the grant top-up — durably
/// debited but tracked only in the ephemeral pump escrow ledger, which dies
/// with the crash — is never refunded and no settle fires (billed = 0), so the
/// invoker is permanently OVER-charged the cumulative grant. Bumping the record
/// makes reconcile refund `open + Σgrants`. A stream that reserved zero escrow
/// at open (declared estimate 0) persisted no record; the first grant CREATES
/// one (escrow-only: empty `ucan_cid`, zero counter) so the top-up is still
/// crash-covered.
///
/// [`commit_class_s_compensating`](crate::context::actor::class_s::ClassSCell::commit_class_s_compensating)
/// (NOT the keep variant) is the correct combinator: on persist failure it
/// SNAPSHOT-RESTORES the Class-S record bump AND runs the Class-C compensation
/// to reverse the budget debit — both undone together, so a failed grant leaves
/// budget and record consistent. The keep variant's Class-C-only compensation
/// cannot reach the Class-S record, which would leave the record over-stating
/// the reversed budget.
///
/// # Errors
///
/// Propagates [`ContextError`] for `EscrowOverflow` (arithmetic) and
/// `InsufficientFunds` (balance), plus any fail-closed persist failure.
pub async fn reserve_stream_grant_escrow(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    member_did: &DID,
    request_id: scp_protocol::context::outlets::stream::RequestId,
    cost_per_chunk: Amount,
    grant: u32,
) -> Result<Amount, ContextError> {
    use crate::context::outlets::dispatch::OpenStreamRejection;

    // Zero-cost / Query outlets, or a zero grant: no debit, no balance
    // consultation, no persist (spec: "no top-up is performed").
    if cost_per_chunk.value() == 0 || grant == 0 {
        return Ok(Amount::new(0));
    }

    // Overflow is a PURE check on `cost × grant` — done BEFORE any debit so an
    // overflow rejects without consulting or debiting the budget.
    let Some(reserved) = cost_per_chunk.checked_mul(u64::from(grant)) else {
        return Err(invocation_error_to_context(
            OpenStreamRejection::EscrowOverflow.to_invocation_error(),
        ));
    };

    let generation = cell.generation;
    let record_key = hex::encode(request_id);
    let member_owned = member_did.clone();

    // Gate + DEBIT the budget AND bump the durable crash-recovery record under
    // ONE fail-closed persist. The actor processes commands serially, so the
    // check-and-debit is atomic without an external lock. NO velocity /
    // hard-rate token is consumed by a grant, so the only rollback needed on
    // rejection is the (not-yet-applied) debit + record bump.
    cell.commit_class_s_compensating(
        deps,
        context_id,
        |mut view| {
            let state = view.rest_mut();
            let remaining = state.governance.budget_tracker.remaining(&member_owned);
            if reserved.value() > remaining.value() {
                // Insufficient funds: reject BEFORE the debit / record bump.
                return Err(invocation_error_to_context(
                    OpenStreamRejection::InsufficientFunds.to_invocation_error(),
                ));
            }
            if state
                .governance
                .budget_tracker
                .record_spend(&member_owned, reserved)
                .is_err()
            {
                // Defensive: `record_spend` reject (budget drained after the
                // local comparison). The serial actor makes this unreachable,
                // but fail closed.
                return Err(invocation_error_to_context(
                    OpenStreamRejection::InsufficientFunds.to_invocation_error(),
                ));
            }
            // Bump the durable crash-recovery record so reconcile refunds
            // `open + Σgrants` on a hard crash (Class-S). `or_insert_with`
            // covers a stream that reserved zero escrow at open (no record was
            // persisted) — the grant creates an escrow-only record.
            let record = state
                .class_s
                .stream_reservations
                .entry(record_key.clone())
                .or_insert_with(
                    || crate::context::outlets::invoke::StreamReservationRecord {
                        invoker_did: member_owned.clone(),
                        ucan_cid: String::new(),
                        cost_per_chunk,
                        amount_cumulative_reserved: 0,
                        reserved_escrow: Amount::new(0),
                        generation,
                    },
                );
            record.reserved_escrow = record.reserved_escrow.saturating_add(reserved);
            // `value` = the reserved hold returned to the caller; `external` =
            // the same hold the persist-failure compensation reverses on the
            // Class-C budget (the Class-S record bump is restored by the
            // combinator's snapshot).
            Ok((reserved, reserved))
        },
        // On persist failure the combinator has ALREADY snapshot-restored the
        // Class-S record bump; this Class-C compensation reverses the budget
        // debit the failed persist did not make durable.
        async |reserved: Amount, mut view, _deps| {
            view.governance_class_c_mut()
                .budget_tracker_mut()
                .reverse_spend(member_did, reserved);
        },
    )
    .await
}

/// Reverse of [`reserve_stream_grant_escrow`] — CREDIT the budget hold back AND
/// un-bump the durable crash-recovery record, atomically, when a grant apply is
/// rejected (signature / replay / stream-closed) after the reserve debited.
///
/// Both legs must move together or a crash between them re-introduces the exact
/// over-/under-charge asymmetry the reserve's atomic bump closes: crediting the
/// budget while leaving the record bumped would make
/// [`reconcile_stream_reservations`] double-refund the reversed hold. Both
/// operations are saturating (`reverse_spend` / `saturating_sub`), so a
/// double-reverse (a Drop-guard racing an explicit reverse) is a safe no-op.
/// Run under [`commit_class_s_keep`](crate::context::actor::class_s::ClassSCell::commit_class_s_keep):
/// a reverse must never un-reverse, so KEEP-on-persist-failure (the run loop
/// retries the durable write) is the correct direction.
///
/// # Errors
///
/// [`ContextError::PersistenceFailed`] when the fail-closed persist does not
/// land (the credit is KEEP'd in memory — the run loop retries).
pub async fn reverse_stream_grant_escrow(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    member_did: &DID,
    request_id: scp_protocol::context::outlets::stream::RequestId,
    amount: Amount,
) -> Result<(), ContextError> {
    if amount.value() == 0 {
        return Ok(());
    }
    let member_owned = member_did.clone();
    let record_key = hex::encode(request_id);
    cell.commit_class_s_keep(deps, context_id, move |mut view| {
        let state = view.rest_mut();
        state
            .governance
            .budget_tracker
            .reverse_spend(&member_owned, amount);
        if let Some(record) = state.class_s.stream_reservations.get_mut(&record_key) {
            record.reserved_escrow = record.reserved_escrow.saturating_sub(amount);
        }
        Ok(())
    })
    .await
}

// ---------------------------------------------------------------------------
// Streaming close-time settlement (chunk 3c) — the actor-mailbox port of the
// reference `ContextManager::outlet_stream_settle`.
// ---------------------------------------------------------------------------

/// Outcome of [`settle_outlet_stream`] — distinguishes a confused-deputy DROP
/// (which touched nothing, so the handler must NOT flag a mutation) from a
/// real settlement (which mutated owned state and owes a coalesced persist).
#[derive(Debug)]
pub enum StreamSettleOutcome {
    /// The reservation's `generation` no longer matches the live actor (an
    /// import-replace / crash-respawn between reserve and settle). Fix-D: the
    /// settlement STILL captures the §19.15.5 receipt for service already
    /// rendered (H8) against the open-time policy SNAPSHOT, but touches NO owned
    /// state — releasing/refunding against this (possibly replaced) instance
    /// would corrupt the wrong economy, and the durable reserves are left for
    /// the restore-time reconcile sweep. The handler must NOT flag a mutation.
    /// The inner `Option` is the captured receipt (`None` when nothing was
    /// billed / no adapter / policy snapshot / capture failed).
    CapturedWithoutMutation(Option<PaymentReceipt>),
    /// The settlement ran on the matching live instance; it released/refunded
    /// the owned reserves, CLEARED the crash-recovery record, and captured the
    /// receipt. The inner `Option` is the captured receipt (`None` when nothing
    /// was billed / no adapter / capture failed). Owed a coalesced persist.
    Settled(Option<PaymentReceipt>),
    /// SCP-OUT-046 CRITICAL (pass-3) — the idempotent no-op: a witness-bearing
    /// xctx settle whose durable `settled` flag was ALREADY set by a prior settle
    /// (a concurrent live seal task or a crash-recovery sweep), observed by the
    /// AUTHORITATIVE pre-commit read at the top of [`settle_outlet_stream`]. The
    /// money moved EXACTLY ONCE on that first settle, so this settle skips the
    /// ENTIRE money move — NO persist and NO capture run. The caller still
    /// resolves `Committed` (the money is durably accounted), but the handler
    /// flags NO mutation (unchanged owned state), so no spurious Class-C persist
    /// is scheduled.
    ///
    /// DISTINCT from `Settled(None)`: that is a genuine FIRST settle that moved
    /// money (release/refund + record clear) but captured no receipt (zero-cost
    /// / no adapter / capture failed) — owed a persist. `AlreadySettled` touched
    /// nothing at all. Separating them is why the pre-commit read is
    /// authoritative even across a persist failure: an in-closure `bool` return
    /// is discarded by `commit_class_s_keep` on a persist `Err`
    /// (`persist_state_fail_closed(..).map(|()| value)` only maps on `Ok`), which
    /// would let the external capture re-run and double-bill.
    AlreadySettled,
}

/// §5.4.5 close-time economic settlement of a streaming-native invocation, run
/// inside the per-context actor on owned state.
///
/// # Confused-deputy guard
///
/// The reservation was made against a specific actor-instance `generation`. If
/// this actor's generation differs, the original instance was despawned and a
/// NEW instance respawned for the same `context_id` between reserve and settle
/// (an import replace / node teardown+respawn). Releasing the cumulative counter
/// or refunding budget against THIS instance's owned state would corrupt the
/// WRONG context's economy. So on a mismatch the settlement does NOT touch owned
/// state — it returns
/// [`StreamSettleOutcome::CapturedWithoutMutation`](StreamSettleOutcome::CapturedWithoutMutation):
/// it STILL captures the §19.15.5 receipt for rendered service against the
/// open-time `economic_policy_snapshot` only (a payment-adapter call that mutates
/// no owned Class-S state — H8 "service rendered is billed", matching the
/// no-actor fallback), but SKIPS the cumulative-counter release and the budget
/// refund. The unspent escrow and counter of the original (crash-restored)
/// reservation are instead reconciled by the durable [`StreamReservationRecord`]
/// and its restore sweep ([`reconcile_stream_reservations`]), which owns THIS
/// context's own state. `generation` is a Class-C structural field read through
/// the cell `Deref`.
///
/// Order (matches the reference "release FIRST"): (1) RELEASE the unspent R4
/// HIGH-1 cumulative-counter reserve back to the owned §7.3.8 `AmountCumulative`
/// counter, and (2) REFUND the unspent escrow to the invoker's budget tracker —
/// both under ONE fail-closed
/// [`commit_class_s_keep`](crate::context::actor::class_s::ClassSCell::commit_class_s_keep)
/// so the two durable bookkeeping mutations land atomically; then (3) capture
/// the §19.15.5 `PaymentReceipt` for the EXACT billed amount off-persist,
/// against the LIVE per-context economic policy (falling back to the open-time
/// [`EconomicPolicySnapshot`](crate::context::outlets::invoke::EconomicPolicySnapshot)
/// only when the live policy is absent — H8 "service rendered is billed").
///
/// Capture runs INDEPENDENTLY of the release/refund persist: a persist failure
/// is KEEP'd in memory (the actor run loop retries the durable write) and logged,
/// and capture still proceeds. Returns the captured receipt, or `None` when
/// nothing was billed, no payment adapter / policy is configured, or capture
/// failed (a `PaymentCaptureFailed` local event records the failure — the billed
/// budget is NOT reversed).
///
/// # Exactly-once billing — the two-layer model (SCP-OUT-046)
///
/// The external payment capture is NOT transactional with the durable owned
/// state, so exactly-once is enforced by two complementary layers:
///
/// 1. **The durable `settled` flag (concurrent guard, same-process,
///    authoritative).** For a witness-bearing xctx settle the flag is read at the
///    TOP of this function (pre-commit, through the cell `Deref`) and set inside
///    the money-move persist. Because the per-context actor serializes every
///    settle through its mailbox, this read wins any CONCURRENT double-settle race
///    (two overlapping recovery sweeps, or a sweep racing the live seal task): the
///    first settle moves the money + sets the flag; every later settle observes it
///    and returns [`StreamSettleOutcome::AlreadySettled`] BEFORE any persist or
///    capture. The read is deliberately pre-commit — an in-closure gate cannot
///    survive a persist `Err` (`commit_class_s_keep` discards the closure's return
///    on failure), which would let the external capture re-run and double-bill.
///
/// 2. **The payment adapter idempotency key (crash-window layer — a REQUIRED
///    ADAPTER CONTRACT, not a runtime guarantee).** The flag cannot close the
///    unavoidable CRASH window: a first settle that captures its receipt, then
///    fails the money-move persist, then crashes before the run-loop retry lands,
///    leaves the durable witness at `settled == false`, so crash recovery
///    re-settles and re-captures. The runtime does NOT itself close this window:
///    it does not maintain a capture-dedup ledger keyed by `request_id`. What the
///    runtime provides is the STABLE IDEMPOTENCY KEY — every capture flows through
///    [`authorize_and_capture_stream_billed`], which sets
///    [`PaymentMetadata::idempotency_key`](crate::economy::adapter::PaymentMetadata::idempotency_key)
///    to the stream `request_id` on `authorize`, and (because `capture` carries no
///    key of its own) lets capture idempotency ride the authorization identity
///    derived from that keyed authorize. The `request_id` is stable across the
///    crash (recovery rebuilds the identical settlement from the durable witness),
///    so a crash-window re-run reconstructs the identical authorize key.
///
///    Whether that re-run actually bills ONCE therefore DEPENDS ENTIRELY on the
///    INJECTED [`PaymentAdapter`](crate::economy::adapter::PaymentAdapter): exactly-once
///    across a crash requires the adapter to (a) DEDUP `authorize` on
///    `idempotency_key` AND (b) be IDEMPOTENT on `capture` of an already-captured
///    authorization. An adapter that ignores the key WILL double-bill across a
///    crash and the runtime cannot detect or prevent it. This is the
///    MUST-honor adapter contract stated on the trait (see
///    [`PaymentAdapter::authorize`](crate::economy::adapter::PaymentAdapter::authorize)
///    /
///    [`PaymentAdapter::capture`](crate::economy::adapter::PaymentAdapter::capture)).
///    A durable "captured" sub-flag would NOT help — capture is external and
///    non-transactional, so a sub-flag would only shrink, never close, the window.
///    The RUNTIME-ENFORCED root close is a runtime capture-dedup ledger keyed by
///    `request_id`, tracked as the follow-up
///    <https://github.com/limn-works/scp/issues/2156>; until it lands, crash-window
///    exactly-once is a delegated adapter contract, not a runtime guarantee.
#[allow(
    clippy::too_many_lines,
    reason = "one linear close-time settlement: unspent math + live-policy read + \
              combined release/refund persist + off-persist capture with capture-failure \
              recording — splitting it would scatter the fixed ordering the doc-comment pins"
)]
pub async fn settle_outlet_stream(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    settlement: crate::context::outlets::invoke::StreamSettlement,
    generation: u64,
    // SCP-OUT-046 CRITICAL — the cross-context streaming-saga witness key. `Some`
    // ⇒ this settle reads `xctx_committed_stream_outputs[saga_id].settled` FIRST
    // (in-closure, actor-serialized ⇒ authoritative): if already `true` a prior
    // settle moved the money exactly once, so the WHOLE money move (release +
    // refund + capture) is a no-op; otherwise it moves the money AND flips
    // `settled` to `true` in the SAME Class-S persist (atomic money+flag; the flag
    // is THE xctx double-refund guard, closing the concurrent-double-settle TOCTOU
    // between two recovery sweeps or a sweep racing the live seal task). On a
    // generation mismatch it instead DEFERS the entire settlement (no capture) so
    // crash recovery completes it exactly once against the restored instance
    // rather than double-billing.
    witness_saga_id: Option<&crate::context::supervisor::saga_journal::SagaId>,
) -> StreamSettleOutcome {
    // Destructure up front so the Fix-D generation-mismatch branch below can
    // read the settlement for its snapshot-policy capture. `reserved`
    // (= billed + refund) is the TOTAL escrow hold the pump accrued over the
    // stream's life — the open-time hold PLUS every accepted credit-grant
    // top-up (`apply_reserved_top_up` extends the same ledger `reserved` is read
    // from at close), NOT the open-time hold alone. The clean path operates on
    // `billed_amount` / `refund_amount` (not `reserved`); `reserved` is the
    // audit/receipt-provenance figure, kept here only to assert the money-
    // conservation invariant below. (Record detection uses `has_record` —
    // whether an entry actually exists — NOT `reserved > 0`.)
    let crate::context::outlets::invoke::StreamSettlement {
        context_id,
        invoker_did,
        reserved,
        billed_amount,
        refund_amount,
        billed_count,
        request_id,
        economic_policy_snapshot,
        amount_cumulative_reserved,
        ucan_cid,
        cost_per_chunk,
        ..
    } = settlement;

    // Money-conservation invariant: the total hold is exactly billed + refund
    // (open + Σgrants). The settlement is CONSTRUCTED this way at pump close, so
    // a violation is a runtime-internal bug, not attacker input — a debug assert
    // documents + guards it without a release-build cost.
    debug_assert_eq!(
        reserved.value(),
        billed_amount.value().saturating_add(refund_amount.value()),
        "StreamSettlement.reserved must equal billed + refund"
    );

    // SCP-OUT-046 CRITICAL (pass-3) — AUTHORITATIVE pre-commit idempotency read.
    // For a witness-bearing xctx settle, read the durable `settled` flag through
    // the cell `Deref` BEFORE the commit block. The per-context actor serializes
    // every settle for this context through its mailbox, so no other settle
    // interleaves within this single handler turn — this read is authoritative and
    // wins any concurrent-double-settle race (two overlapping recovery sweeps, or a
    // sweep racing the live seal task).
    //
    // It is placed BEFORE the fail-closed commit ON PURPOSE. `commit_class_s_keep`
    // runs `persist_state_fail_closed(..).map(|()| value)`: on a persist FAILURE the
    // closure's return is DISCARDED (mapped only on `Ok`), so an in-closure "already
    // settled" signal cannot survive a persist `Err`. If the money move were gated
    // only inside the closure, an already-settled settle whose (redundant) persist
    // then failed would fall through to the external capture below and bill a SECOND
    // time — the xctx path has NO `stream_reservations` reconcile net to dedup the
    // capture (streaming saga runs with `settlement_sink = None`). Reading the flag
    // here, before any persist, closes that window: if a prior settle already moved
    // the money exactly once, skip the WHOLE settlement (no persist, no capture) and
    // resolve `Committed` via `AlreadySettled`. The first-settle atomic money+flag
    // SET stays inside the closure below (money and `settled` land in ONE persist).
    if let Some(sid) = witness_saga_id
        && cell
            .class_s
            .xctx_committed_stream_outputs
            .get(sid)
            .is_some_and(|w| w.settled)
    {
        tracing::debug!(
            context_id = %context_id,
            request_id = %hex::encode(request_id),
            "outlet stream settlement (xctx saga): witness already settled \
             (authoritative pre-commit read) — skipping the whole settlement \
             (no persist, no capture)"
        );
        return StreamSettleOutcome::AlreadySettled;
    }

    // Money-conservation fail-closed (crypto): `billed_amount` and the
    // (`billed_count`, `cost_per_chunk`) pair are INDEPENDENT settlement fields,
    // but the captured `PaymentReceipt` (a money artifact) must never bill MORE
    // than `cost_per_chunk × billed_count`. Cap the captured amount at that
    // per-chunk-derived figure so a settlement constructed with an inflated
    // `billed_amount` can never OVER-charge the invoker (a `cost × count`
    // overflow derives `0` — capture nothing rather than a bogus amount). `min`
    // only ever REDUCES the captured amount; an under-stated `billed_amount`
    // (e.g. a zero-cost / release-only settlement) is left as-is. The refund
    // leg (`refund_amount`, computed independently as `reserved − billed`) is
    // unaffected.
    let derived_billed = cost_per_chunk
        .value()
        .checked_mul(u64::from(billed_count))
        .unwrap_or(0);
    let billed_amount = Amount::new(billed_amount.value().min(derived_billed));

    // Fix-D confused-deputy handling. The reservation was made against a
    // specific actor-instance `generation`. If this actor's generation differs,
    // the original instance was despawned and a NEW one respawned for the same
    // `context_id` (crash-respawn or import-replace) between reserve and settle.
    // We CANNOT distinguish those here, and releasing/refunding against THIS
    // instance's owned state could corrupt the WRONG context's economy — so we
    // touch NO owned state. But the service WAS rendered (H8), so we STILL
    // capture the §19.15.5 receipt against the OPEN-TIME policy SNAPSHOT (never
    // the live per-context policy — this may be a different context), via the
    // supervisor payment adapter, exactly like the no-actor fallback in
    // `settle_outlet_stream_via_actor`. The durable escrow hold + cumulative
    // counter reserve are left in place: on a crash-restore the restore-time
    // `ReconcileStreamReservations` sweep releases them from the persisted
    // recovery record; on an import-replace they were already dropped with the
    // replaced state (the record is stripped on export). Either way this path
    // does NOT clear the record.
    if generation != cell.generation {
        // SCP-OUT-046 CRITICAL — a witness-bearing cross-context streaming
        // settlement DEFERS ENTIRELY on a generation mismatch: touch no owned
        // state AND do NOT capture. Touching owned state is unsafe here (this may
        // be the WRONG respawned context), so the release/refund MUST defer to
        // recovery on the restored instance regardless. Bundling the capture into
        // that deferral keeps the whole settlement single-shot and avoids relying
        // on the payment adapter to collapse an eager capture here against
        // recovery's — the durable witness stays `settled == false`, so crash
        // recovery completes the WHOLE settlement (refund + release + capture)
        // exactly once against the restored instance, using the SAME durable
        // `request_id` as this call's idempotency key.
        if witness_saga_id.is_some() {
            tracing::debug!(
                context_id = %context_id,
                reserved_generation = generation,
                live_generation = cell.generation,
                "outlet stream settlement (xctx saga) landed on a replaced instance — \
                 deferring the whole settlement to crash recovery (witness left unsettled)"
            );
            return StreamSettleOutcome::CapturedWithoutMutation(None);
        }
        tracing::debug!(
            context_id = %context_id,
            reserved_generation = generation,
            live_generation = cell.generation,
            "outlet stream settlement landed on a replaced actor instance — \
             capturing the rendered bill against the open-time policy snapshot \
             without touching owned state (Fix-D)"
        );
        let (Some(adapter), Some(policy)) = (
            deps.payment_adapter.as_ref(),
            economic_policy_snapshot.map(|snap| snap.policy),
        ) else {
            return StreamSettleOutcome::CapturedWithoutMutation(None);
        };
        if billed_amount.value() == 0 {
            return StreamSettleOutcome::CapturedWithoutMutation(None);
        }
        return match authorize_and_capture_stream_billed(
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
                    request_id = %hex::encode(request_id),
                    billed = billed_amount.value(),
                    receipt_id = %hex::encode(receipt.receipt_id),
                    "outlet stream settlement captured PaymentReceipt on a replaced \
                     instance (reserves left for the reconcile sweep)"
                );
                StreamSettleOutcome::CapturedWithoutMutation(Some(receipt))
            }
            Err(err) => {
                // H8: service rendered but capture failed on a replaced instance.
                // There is no trustworthy owned receive buffer to emit a
                // `PaymentCaptureFailed` event into here (this may be the wrong
                // context) — log only; the reserve record stays for the sweep.
                tracing::warn!(
                    context_id = %context_id,
                    "outlet stream settlement: payment capture failed on a replaced \
                     instance: {err}"
                );
                StreamSettleOutcome::CapturedWithoutMutation(None)
            }
        };
    }

    // ---- Matching live instance: the clean close-time settlement. ----

    // The UNSPENT cumulative reserve to release: `reserved − billed_count ×
    // cost_per_chunk` (saturating). A degenerate `billed × cost` overflow FAILS
    // CLOSED — releases nothing, leaving the counter conservatively over-charged
    // (never under-charged). Mirrors
    // [`CounterReserveSettlement::unspent_release_amount`](crate::context::outlets::dispatch::CounterReserveSettlement::unspent_release_amount).
    let unspent_release = u64::from(billed_count)
        .checked_mul(cost_per_chunk.value())
        .map_or(0, |billed| {
            amount_cumulative_reserved.saturating_sub(billed)
        });
    // An empty `ucan_cid` (legacy / test caller with no durable counter
    // reservation) has no counter to release to.
    let should_release = unspent_release > 0 && !ucan_cid.is_empty();

    // Read the LIVE per-context economic policy for capture BEFORE the commit
    // borrows the cell. Prefer live (it may have changed via governance since
    // open); fall back to the open-time snapshot (H8) when the live policy is
    // absent. Routed through the non-persisting `class_c_view()`.
    let capture_policy = cell
        .class_c_view()
        .governance_class_c_mut()
        .economic_policy_mut()
        .clone()
        .or_else(|| economic_policy_snapshot.map(|snap| snap.policy));

    // Release the cumulative reserve + refund the escrow under ONE fail-closed
    // persist. Both are owned-state writes; combining them means either both
    // survive a coalesce-window crash or the KEEP'd in-memory mutation is
    // retried by the run loop.
    // Fix-D: the crash-recovery record's WHOLE purpose is refunding UNSPENT
    // escrow on a crash where this clean settle never runs. This clean terminal
    // has fully accounted the escrow (release + refund above), so the record is
    // now stale and MUST be removed in the SAME persist — otherwise a later
    // restart's reconcile sweep would see it and double-release. Remove it
    // UNCONDITIONALLY (not gated on `reserved`/`cum`): a record can exist even
    // when the ledger-derived `reserved` settled to `0` — e.g. a zero-escrow-
    // open stream whose first grant CREATED a record and then had its apply
    // REJECTED (the reverse un-bumped `reserved_escrow` to 0 but left the entry)
    // — and that 0-record must not linger in durable state. `has_record` (read
    // before the commit borrows the cell) keeps a truly recordless stream
    // (zero-cost, no grant) skipping the persist entirely; the removal inside is
    // a no-op if somehow absent. Removing a record NEVER changes budget: the
    // refund is the independent `refund_amount` reverse above; the record is
    // only the crash-recovery figure a clean settle supersedes.
    let request_key = hex::encode(request_id);
    let has_record = cell.class_s.stream_reservations.contains_key(&request_key);
    // SCP-OUT-046 CRITICAL: a witness-bearing xctx settle ALWAYS persists (even a
    // zero-money settle) so the `settled` flag is flipped atomically with any
    // money move — recovery reads the flag to know the settlement completed. The
    // already-settled case has ALREADY returned above (the authoritative
    // pre-commit read), so reaching here is necessarily the FIRST settle for this
    // witness; the closure just SETS `settled` in the same persist as the money.
    let witness_for_commit = witness_saga_id.cloned();
    if should_release || refund_amount.value() > 0 || has_record || witness_for_commit.is_some() {
        let invoker_for_commit = invoker_did.clone();
        let ucan_for_commit = ucan_cid.clone();
        let commit_result = cell
            .commit_class_s_keep(deps, &context_id, move |mut view| {
                let state = view.rest_mut();
                // SCP-OUT-046 CRITICAL — FIRST-settle atomic money+flag SET. The
                // authoritative idempotency decision happened PRE-COMMIT (above): an
                // already-settled witness returned `AlreadySettled` before this block,
                // and the per-context actor serializes settles so no other settle
                // interleaves between that read and this persist. Reaching here is
                // therefore the first settle — flip `settled` in the SAME Class-S
                // persist as the money move below so money and flag land (or KEEP)
                // together, making `settled` the durable, atomic record that the
                // refund + §7.3.8 counter release actually happened. (Gating the money
                // move on the flag INSIDE the closure would be unsound on its own: a
                // fallible persist discards the closure's return on `Err`, so a
                // persist-failed already-settled settle could still reach the external
                // capture below — the pre-commit read closes exactly that window.)
                // NOTE (R2, H8-accepted cost): `settled` flips HERE, in the
                // money-move persist, BEFORE and INDEPENDENT of the external
                // capture below. So a capture that fails after this persist lands
                // is a terminal lost-bill (future re-settles see `settled == true`
                // and short-circuit, never re-capturing) — a deliberate
                // best-effort-once tradeoff, detailed at the capture-failure `Err`
                // branch below.
                if let Some(sid) = witness_for_commit.as_ref()
                    && let Some(w) = state.class_s.xctx_committed_stream_outputs.get_mut(sid)
                {
                    w.settled = true;
                }
                if should_release {
                    state
                        .class_s
                        .caveat_counters
                        .entry(ucan_for_commit)
                        .or_default()
                        .release(CaveatKind::AmountCumulative, unspent_release);
                }
                if refund_amount.value() > 0 {
                    state
                        .governance
                        .budget_tracker
                        .reverse_spend(&invoker_for_commit, refund_amount);
                }
                // Unconditionally drop the crash-recovery record on the clean
                // terminal (no-op if absent) — the double-release guard.
                state.class_s.stream_reservations.remove(&request_key);
                Ok(())
            })
            .await;
        if let Err(err) = commit_result {
            // KEEP semantics: the in-memory release/refund IS applied; the run loop
            // retries the durable write. Capture runs regardless (H8). If this FIRST
            // settle's persist fails and the process crashes before the retry lands,
            // the durable witness stays `settled == false` and crash recovery
            // re-settles with the SAME durable `request_id` — the payment adapter's
            // idempotency key collapses the re-capture (the two-layer exactly-once
            // model; see the fn doc-comment).
            tracing::warn!(
                context_id = %context_id,
                request_id = %hex::encode(request_id),
                "outlet stream settlement: release/refund persist failed (kept in memory): {err}"
            );
        }
    }

    // Capture the §19.15.5 PaymentReceipt for the EXACT billed amount. Skip when
    // nothing was billed or no adapter/policy is configured (the legitimate
    // zero-cost / no-payment-rail default).
    let (Some(adapter), Some(policy)) = (deps.payment_adapter.as_ref(), capture_policy.as_ref())
    else {
        return StreamSettleOutcome::Settled(None);
    };
    if billed_amount.value() == 0 {
        return StreamSettleOutcome::Settled(None);
    }
    match authorize_and_capture_stream_billed(
        adapter.as_ref(),
        policy,
        &invoker_did,
        billed_amount,
        request_id,
        &context_id,
    )
    .await
    {
        Ok(receipt) => {
            tracing::debug!(
                request_id = %hex::encode(request_id),
                billed = billed_amount.value(),
                billed_count,
                receipt_id = %hex::encode(receipt.receipt_id),
                "outlet stream settlement captured PaymentReceipt"
            );
            StreamSettleOutcome::Settled(Some(receipt))
        }
        Err(err) => {
            // Capture failed AFTER service was rendered (H8): the billed budget
            // is NOT reversed — only the unspent refund (already applied above)
            // is returned. Surface a `PaymentCaptureFailed` LOCAL event for the
            // reconciliation audit trail (ADR-051 §6 — per-payee, non-durable).
            //
            // R2 — capture-failure LOST-BILL, the explicit H8-accepted cost. On a
            // witness-bearing xctx settle the durable `settled` flag was flipped to
            // `true` in the money-move persist ABOVE, BEFORE (and independent of)
            // this external capture. So a transient `capture` failure here is
            // terminal for the bill: `settled == true` means every FUTURE re-settle
            // short-circuits at the authoritative pre-commit read
            // (`AlreadySettled`) and NEVER re-captures. Capture is deliberately
            // BEST-EFFORT-ONCE — the failed bill is reconciled out-of-band via this
            // `PaymentCaptureFailed` audit event, NOT auto-retried — an
            // invoker-favoring tradeoff (the invoker is never re-charged, the payee
            // absorbs a rail-transient loss surfaced in the audit trail) chosen over
            // a retry loop that could double-bill or wedge settlement. This is the
            // accepted cost of flipping the durable flag pre-capture (which is
            // itself REQUIRED so recovery can tell a completed settlement from an
            // un-run one); it is documented behavior, not a defect to "fix" by
            // reversing budget or re-capturing.
            tracing::warn!(
                context_id = %context_id,
                "outlet stream settlement: payment capture failed: {err}"
            );
            let event = scp_protocol::context::membership::ContextEvent::PaymentCaptureFailed {
                action: "outlet_stream".to_owned(),
                actor_did: invoker_did.clone(),
                error: err.to_string(),
                cost: Some(billed_amount.value()),
            };
            crate::context::state::emit_event_into(
                cell.class_c_view().receive_buffer_mut(),
                event,
                &context_id,
                deps.event_tx.as_ref(),
            );
            StreamSettleOutcome::Settled(None)
        }
    }
}

/// Fix-D restore-time streaming crash-recovery sweep core, run inside the
/// per-context actor on owned state.
///
/// Drains `ClassSState.stream_reservations` under ONE fail-closed
/// [`commit_class_s_keep`](crate::context::actor::class_s::ClassSCell::commit_class_s_keep).
/// For each unresolved record it REFUNDS the full `reserved_escrow` to the
/// invoker's `MemberBudgetTracker` (`reverse_spend`, saturating) and RELEASES the
/// full `amount_cumulative_reserved` back to the §7.3.8 `AmountCumulative` counter
/// keyed by `ucan_cid` (`release`, saturating). The billed count is unknown once
/// the pump is gone, so the FULL reserved amounts are returned — conservative:
/// the invoker is never over-charged and the cumulative cap is never
/// over-consumed. Billing for rendered service is authoritative only where a
/// settle actually fired: on a SOFT respawn the pump survived the actor restart
/// and its close-time
/// [`CapturedWithoutMutation`](StreamSettleOutcome::CapturedWithoutMutation)
/// settle captured the manifest-anchored bill before this sweep runs; on a HARD
/// crash (the pump died with the process, no settle ever fired) no manifest
/// reaches settle, so service rendered before the crash is un-billed — the
/// operator absorbs it (the correct, invoker-favoring direction). Either way the
/// sweep never bills; it only returns the unspent reserve. Runs REGARDLESS of
/// generation — a restore overwrites
/// `PerContextState::generation` with a fresh spawn generation, and the reserves
/// are this restored context's OWN state. The releases + the clear land in the
/// SAME persist, so the sweep is idempotent across restarts.
///
/// Returns the number of records reconciled.
///
/// # Errors
///
/// [`ContextError::PersistenceFailed`] if the fail-closed persist did not land.
/// The in-memory releases + clear are KEEP'd regardless (the run loop retries
/// the durable write; a restart before it lands re-runs the sweep from the
/// restored record — idempotent).
pub(in crate::context) async fn reconcile_stream_reservations(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
) -> Result<usize, ContextError> {
    let count = cell.class_s.stream_reservations.len();
    if count == 0 {
        return Ok(0);
    }
    cell.commit_class_s_keep(deps, context_id, move |mut view| {
        let state = view.rest_mut();
        // Take the map out so the per-record reversal can borrow the sibling
        // governance / caveat-counter state mutably without aliasing.
        let records = std::mem::take(&mut state.class_s.stream_reservations);
        for record in records.into_values() {
            if record.reserved_escrow.value() > 0 {
                // Refund the FULL open-time escrow hold — the pump is gone and
                // the billed count is unknown. Saturating (`reverse_spend`), so a
                // benign over-refund of an already-settled hold is a no-op.
                state
                    .governance
                    .budget_tracker
                    .reverse_spend(&record.invoker_did, record.reserved_escrow);
            }
            if record.amount_cumulative_reserved > 0 && !record.ucan_cid.is_empty() {
                // Release the FULL cumulative reserve back to the counter.
                state
                    .class_s
                    .caveat_counters
                    .entry(record.ucan_cid)
                    .or_default()
                    .release(
                        CaveatKind::AmountCumulative,
                        record.amount_cumulative_reserved,
                    );
            }
        }
        Ok(())
    })
    .await?;
    Ok(count)
}

/// §5.4.5 open-time escrow REVERSAL on actor-owned state — the actor-mailbox
/// port of the reference `ContextManager::outlet_stream_reverse_spend`.
///
/// Credits `amount` back to `member_did`'s
/// [`MemberBudgetTracker`](scp_protocol::economy::budget::MemberBudgetTracker)
/// via [`reverse_spend`](scp_protocol::economy::budget::MemberBudgetTracker::reverse_spend)
/// — infallible / SATURATING at `0`, so a double-refund (a Drop-guard reversal
/// after an explicit settlement already returned the hold) is a safe no-op —
/// under a fail-closed
/// [`commit_class_s_keep`](crate::context::actor::class_s::ClassSCell::commit_class_s_keep),
/// so the returned budget survives a coalesce-window crash the same way the
/// original debit does.
///
/// # Errors
///
/// [`ContextError::PersistenceFailed`] when the fail-closed persist does not land
/// (the credit is KEEP'd in memory — the run loop retries the durable write).
pub async fn reverse_stream_escrow(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    member_did: &DID,
    amount: Amount,
) -> Result<(), ContextError> {
    let member_did_owned = member_did.clone();
    cell.commit_class_s_keep(deps, context_id, move |mut view| {
        view.rest_mut()
            .governance
            .budget_tracker
            .reverse_spend(&member_did_owned, amount);
        Ok(())
    })
    .await
}

/// Authorize + capture the exact `billed_amount` for a closed §5.4.5 stream —
/// the actor-mailbox port of the `authorize_dyn → capture_dyn` sequence in the
/// reference `ContextManager::outlet_stream_settle`.
///
/// The streaming billed amount (`cost_per_chunk × billed_count`) is the
/// AUTHORITATIVE figure — NOT a fresh policy evaluation — so it is authorized and
/// captured verbatim; the receipt reflects exactly what the invoker consumed.
/// Shared by the on-actor
/// [`settle_outlet_stream`] and the supervisor-side no-actor fallback
/// [`Supervisor::settle_outlet_stream_via_actor`](crate::context::supervisor::Supervisor::settle_outlet_stream_via_actor).
///
/// # Idempotency (both legs)
///
/// The stable `request_id` is set as
/// [`PaymentMetadata::idempotency_key`](crate::economy::adapter::PaymentMetadata::idempotency_key)
/// on the `authorize_dyn` leg. `capture_dyn` takes ONLY `&PaymentAuthorization`
/// — the trait exposes NO capture-side metadata/idempotency parameter — so
/// capture idempotency rides the AUTHORIZATION IDENTITY rather than a second
/// key: a key-honoring adapter dedups `authorize` on `request_id` and returns
/// the SAME [`PaymentAuthorization`](crate::economy::adapter::PaymentAuthorization)
/// (same `auth_id`) for a repeated `request_id`, and a conforming adapter is
/// idempotent on `capture` of that already-captured authorization (returning the
/// same receipt or [`PaymentError::AlreadyCaptured`](crate::economy::adapter::PaymentError::AlreadyCaptured)).
/// Because BOTH the authorize key AND the capture authorization derive from the
/// one stable `request_id`, a crash-window re-run of this function reconstructs
/// the identical authorize key and is dedup-able by a key-honoring adapter at
/// BOTH points. This is a REQUIRED ADAPTER CONTRACT — the runtime keeps no
/// capture-dedup ledger of its own (root close tracked in
/// <https://github.com/limn-works/scp/issues/2156>); see the exactly-once
/// two-layer model on [`settle_outlet_stream`].
///
/// # Errors
///
/// Propagates the adapter's [`PaymentError`](crate::economy::adapter::PaymentError)
/// from either the authorize or the capture leg (service was rendered — the
/// caller records a `PaymentCaptureFailed` and does NOT reverse the budget).
pub async fn authorize_and_capture_stream_billed(
    adapter: &dyn crate::economy::adapter::PaymentAdapterDyn,
    policy: &scp_protocol::economy::types::EconomicPolicy,
    invoker_did: &DID,
    billed_amount: Amount,
    request_id: scp_protocol::context::outlets::stream::RequestId,
    context_id: &str,
) -> Result<PaymentReceipt, crate::economy::adapter::PaymentError> {
    let metadata = crate::economy::adapter::PaymentMetadata {
        action_type: scp_protocol::economy::types::PaidActionType::OutletCall,
        context_id: Some(context_id.to_owned()),
        idempotency_key: request_id,
    };
    let auth = adapter
        .authorize_dyn(
            invoker_did,
            &policy.payee,
            billed_amount,
            policy.cost_schedule.currency,
            metadata,
        )
        .await?;
    adapter.capture_dyn(&auth).await
}

// ---------------------------------------------------------------------------
// Phase 3a: settle_outlet_economy_capture (actor handler entry point)
// ---------------------------------------------------------------------------

/// Phase 3 of the outlet economy pipeline on executor SUCCESS, run inside
/// the per-context actor on owned state. Performs post-invocation
/// participation bookkeeping + consequence enforcement, then captures the
/// escrowed payment, and finally commits the ticket.
///
/// Returns the triggered consequences and the optional payment receipt.
///
/// `downward_auth_sink` (ADR-049 §9, RED-CS3): a CALLER-OWNED
/// `&mut Option<ClassSCommitToken>` that this function POPULATES with a
/// fail-closed-persist obligation if consequence enforcement performed a
/// downward-authorization mutation (a `suspended_capabilities` GROW or an
/// `AssignRole` `member_capabilities` replacement). The token is a caller-owned
/// sink rather than part of the return value SO IT SURVIVES THE PAYMENT-CAPTURE
/// ERROR PATH: the mutation is applied in memory BEFORE the fallible payment
/// capture, and on capture failure this function returns `Err` early — a
/// returned token would be STRANDED/DROPPED by that `?` (tripping the token's Drop
/// guard on a path that legitimately must still persist, or losing the obligation
/// entirely — the RED-CS3 hole). With the token living in the caller's `Option`,
/// passed by `&mut`, an early `return Err` here does NOT drop it; the cell-holding
/// caller ([`settle_outlet_economy`]) commits it fail-closed AFTER the call
/// regardless of Ok/Err. On payment-capture failure the ticket is reversed (budget
/// / velocity / rate-limit) and the error surfaced; the in-memory downward-auth
/// mutation is NOT reversed (keep-direction).
///
/// # Errors
///
/// Propagates [`ContextError::PermissionDenied`] when payment capture
/// fails after a successful execution.
pub async fn settle_outlet_economy_capture(
    mut view: crate::context::actor::class_s::ClassCMut<'_>,
    deps: &ActorDeps,
    context_id: &str,
    invoker_did: &DID,
    ticket: OutletEconomyTicket,
    downward_auth_sink: &mut Option<crate::context::actor::class_s::ClassSCommitToken>,
) -> Result<
    (
        Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
        Option<PaymentReceipt>,
    ),
    ContextError,
> {
    let event_log = &deps.event_log;
    let event_tx = deps.event_tx.clone();
    let clock = deps.clock.as_ref();
    let payment_adapter = deps.payment_adapter.clone();

    let now = clock.now_secs();
    let (events_for_consequences, convergent_now) =
        crate::context::governance_logic::event_log_entries_for_consequences(
            view.receive_buffer_mut(),
            context_id,
            now,
            event_log.as_ref(),
        );
    let consequence_rules = view
        .governance_class_c_mut()
        .consequence_rules_mut()
        .clone();

    let consequences = post_outlet_invocation_bookkeeping(
        &events_for_consequences,
        invoker_did,
        context_id,
        now,
        convergent_now,
        view.governance_class_c_mut().participation_cache_mut(),
        &consequence_rules,
    );

    // Consequence path (ADR-049 §9 / RED-CS3). `consequence_split()` yields the
    // consequence-engine split — disjoint Class-C / structural borrows plus the
    // consequence-only `ConsequenceRoleStateMut` (the ONE role view exposing the
    // downward-auth GROW + demotion) — from the field-granular cell view, with NO
    // whole `&mut PerContextState` and NO `&mut` reach into any PRIVATIZED Class-S
    // sub-struct. (`ceiling` is read-only even here; the GROW
    // `suspended_capabilities` / the `member_capabilities` demotion are applied
    // through methods.) Consequence EVALUATION stays best-effort (the run loop
    // coalesce-persists); only a downward-auth OUTCOME owes a fail-closed persist,
    // which the cell-holding caller performs when `downward_auth_applied` is set.
    let mut split = view.consequence_split();
    // The GROW arms the caller-owned `downward_auth_sink` directly (GAP-A closed),
    // so the mutation's fail-closed-persist obligation survives the payment-capture
    // error path below (a returned token would be stranded/dropped by the early
    // `return Err` — RED-CS3).
    let _ = crate::context::governance_logic::enforce_triggered_consequences(
        &mut split,
        &crate::context::governance_logic::EnforceConsequencesCtx {
            context_id,
            member_did: invoker_did,
            now,
            triggered: &consequences,
            rules: &consequence_rules,
            clock,
            event_log: event_log.as_ref(),
            event_tx: event_tx.as_ref(),
        },
        downward_auth_sink,
    )
    .await;

    let payment_receipt = match (
        payment_adapter.as_ref(),
        ticket.escrow.as_ref(),
        ticket.policy_for_capture.as_ref(),
    ) {
        (Some(adapter), Some(prepared), policy_opt) => {
            match invoke::complete_outlet_payment(
                adapter.as_ref(),
                policy_opt,
                prepared,
                &ticket.metrics_for_capture,
            )
            .await
            {
                Ok(receipt) => receipt,
                Err(capture_err) => {
                    // Reverse the Class-C governance economy bookkeeping through
                    // the field-granular `GovernanceClassCMut` view (no `&mut`
                    // path to any Class-S sub-struct; coalesce-persisted).
                    let gov = view.governance_class_c_mut();
                    if let Some(cost) = ticket.deducted_cost {
                        gov.budget_tracker_mut().reverse_spend(invoker_did, cost);
                    }
                    gov.velocity_tracker_mut()
                        .rollback(invoker_did, ticket.velocity_token);
                    if ticket.needs_hard_rate_limit_refund {
                        gov.hard_rate_limit_mut().refund(invoker_did);
                    }
                    let mut ticket = ticket;
                    ticket.consumed = true;
                    ticket.needs_hard_rate_limit_refund = false;
                    return Err(invocation_error_to_context(capture_err));
                }
            }
        }
        _ => None,
    };

    let _cost = commit_outlet_economy_ticket(ticket);
    Ok((consequences, payment_receipt))
}

// ---------------------------------------------------------------------------
// Phase 3b: rollback_outlet_economy (actor handler entry point)
// ---------------------------------------------------------------------------

/// Phase 3 of the outlet economy pipeline on executor FAILURE, run inside
/// the per-context actor on owned state. Voids any payment escrow hold,
/// then reverses the velocity entry, budget deduction, and hard-rate-limit
/// token consumed by [`reserve_outlet_economy`].
/// Generation-checked Phase-3 rollback. Reverses the reservation against THIS
/// actor's owned state ONLY if the reservation's `generation` still matches the
/// live actor's `state.generation`; on a MISMATCH the actor was despawned and a
/// new instance respawned for the same `context_id` between reserve and this
/// rollback (e.g. an import replace), so refunding velocity / budget /
/// hard-rate-limit against THIS instance's owned state would be a
/// confused-deputy write to the WRONG context instance. On mismatch it voids
/// only the EXTERNAL escrow (the real payment hold the prior instance authorized
/// at reserve) and consumes the ticket — exactly mirroring
/// [`settle_outlet_economy`]'s generation guard, but for the failure/abort path.
///
/// This is the rollback-path counterpart the saga abort handler and the
/// Commit-A idempotency-replay branch use: those paths previously called
/// [`rollback_outlet_economy`] directly, which writes local state
/// unconditionally and would corrupt a respawned (gen N→N+1) instance's economy
/// state. Returns `true` when the local rollback ran (generations matched),
/// `false` when only the external escrow was voided (mismatch).
pub async fn rollback_outlet_economy_generation_checked(
    mut view: crate::context::actor::class_s::ClassCMut<'_>,
    deps: &ActorDeps,
    reservation_generation: u64,
    ticket: OutletEconomyTicket,
) -> bool {
    // `generation` is a Class-C structural field reached through the view; read
    // it via the field-granular accessor (the view holds no whole `&mut`).
    if reservation_generation != *view.generation_mut() {
        // Confused-deputy guard (mirrors `settle_outlet_economy`): the reservation
        // belongs to a now-replaced actor instance. Void only the external
        // escrow and consume; the context-local bookkeeping lived in the gone
        // instance's `PerContextState` and must NOT be touched here.
        ticket
            .void_external_and_consume(deps.payment_adapter.as_ref())
            .await;
        return false;
    }
    rollback_outlet_economy(view, deps, ticket).await;
    true
}

pub async fn rollback_outlet_economy(
    mut view: crate::context::actor::class_s::ClassCMut<'_>,
    deps: &ActorDeps,
    mut ticket: OutletEconomyTicket,
) {
    ticket.consumed = true;

    if let (Some(adapter), Some(prepared)) = (deps.payment_adapter.as_ref(), ticket.escrow.as_ref())
    {
        invoke::void_outlet_escrow(adapter.as_ref(), prepared).await;
    }

    // Reverse the Class-C governance economy bookkeeping through the
    // field-granular `GovernanceClassCMut` view (this helper cannot touch
    // Class-S — it holds no `&mut` path to it).
    let gov = view.governance_class_c_mut();
    gov.velocity_tracker_mut()
        .rollback(&ticket.actor_did, ticket.velocity_token);
    if let Some(cost) = ticket.deducted_cost {
        gov.budget_tracker_mut()
            .reverse_spend(&ticket.actor_did, cost);
    }
    if ticket.needs_hard_rate_limit_refund {
        gov.hard_rate_limit_mut().refund(&ticket.actor_did);
        ticket.needs_hard_rate_limit_refund = false;
    }
}

// ---------------------------------------------------------------------------
// Supervisor-side orchestrator: invoke_outlet_with_economy
// ---------------------------------------------------------------------------

/// Invokes a outlet under the full economy pipeline without holding any
/// per-context lock across the executor future (spec §19.7), in the
/// actor model.
///
/// Orchestrates the three-phase split: dispatch the Phase-1
/// [`OutletsCommand::ReserveOutletEconomy`](crate::context::actor::commands::OutletsCommand::ReserveOutletEconomy)
/// to the context actor (economy reserve on owned state), run the
/// non-`Send` executor supervisor-side via
/// [`invoke_outlet_execute_and_validate`], then dispatch the Phase-3
/// [`OutletsCommand::SettleOutletEconomy`](crate::context::actor::commands::OutletsCommand::SettleOutletEconomy)
/// (capture on success / rollback on failure). The economy bookkeeping
/// never crosses the mailbox as anything but a `Send`
/// [`OutletEconomyReservation`]; the executor never crosses the mailbox at
/// all.
///
/// `reserve` / `settle` are caller-supplied closures that perform the
/// mailbox round-trips (the supervisor owns the actor registry and the
/// command-construction surface); this keeps `outlets_helpers` free of a
/// `&Supervisor` dependency while concentrating the lock-split sequencing
/// in one place.
///
/// # Errors
///
/// Propagates every error variant the reserve / settle handlers and the
/// executor emit (`ContextNotRegistered`, `PermissionDenied`,
/// `RateLimited`, schema/economy/UCAN failures).
// Mirrors the FFI outlet-invocation surface (registry/outlet_id/input/
// invoker_did/timeout_ms/executor) plus the two phase-handoff closures;
// bundling them would only obscure the lock-split sequencing.
#[allow(clippy::too_many_arguments)]
pub async fn invoke_outlet_with_economy<Reserve, ReserveFut, Settle, SettleFut, F, Fut>(
    registry: &OutletRegistry,
    outlet_id: &OutletId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    reserve: Reserve,
    settle: Settle,
    executor: F,
) -> Result<ManagedOutletInvocationOutput, ContextError>
where
    Reserve: FnOnce() -> ReserveFut,
    ReserveFut: Future<Output = Result<OutletEconomyReservation, ContextError>>,
    Settle: FnOnce(OutletSettleRequest) -> SettleFut,
    SettleFut: Future<Output = Result<OutletSettleOutcome, ContextError>>,
    F: FnOnce(serde_json::Value) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
{
    // Phase 1 — economy reserve runs inside the actor on owned state.
    let OutletEconomyReservation {
        handle,
        role_state,
        generation,
        ticket,
    } = reserve().await?;

    // Phase 2 — run the non-Send executor supervisor-side, OFF the actor
    // mailbox, so the actor is free to process other commands and a
    // misbehaving outlet cannot stall the per-context actor loop.
    let outcome = match invoke_outlet_execute_and_validate(
        &handle,
        registry,
        &role_state,
        outlet_id,
        input,
        invoker_did,
        timeout_ms,
        executor,
        // SCP-OUT-028: the manager wrapper does not yet wire a
        // handler-panic sink — the panic guard still recovers panics into
        // `InvocationError::HandlerPanic`; only the §5.4.2 OutletVerified
        // attribution emission is skipped when the sink is `None`.
        None,
    )
    .await
    {
        Ok(o) => o,
        Err(err) => {
            // Phase 3 (rollback) — reverse the reservation in the actor.
            // Inspect the result rather than discarding it: if the settle
            // is unreachable (the actor was despawned during the off-
            // mailbox executor window) the closure is responsible for
            // voiding the external escrow + consuming the ticket (see
            // `settle_outlet_economy_via_actor`), but we still surface the
            // failure to logs — a settle that cannot run is an economy
            // anomaly the operator must see.
            if let Err(settle_err) =
                settle(OutletSettleRequest::Rollback { generation, ticket }).await
            {
                tracing::error!(
                    rollback_error = %settle_err,
                    executor_error = %err,
                    "outlet-economy rollback settle failed after executor error; the settle \
                     closure must have voided any external escrow and consumed the ticket"
                );
            }
            return Err(invocation_error_to_context(err));
        }
    };
    let InvokeExecuteOutcome {
        output,
        input_hash,
        output_hash,
        execution_time_ms,
    } = outcome;

    // Phase 3 (capture) — post-invocation bookkeeping + payment capture
    // in the actor.
    let OutletSettleOutcome {
        consequences,
        payment_receipt,
        cost,
    } = settle(OutletSettleRequest::Capture { generation, ticket }).await?;

    let event = build_outlet_event(
        outlet_id,
        invoker_did,
        execution_time_ms,
        input_hash,
        output_hash,
        cost,
    );

    Ok(ManagedOutletInvocationOutput {
        output,
        event,
        consequences,
        payment_receipt,
    })
}

/// Phase-3 settle request handed to the supervisor-supplied `settle`
/// closure by [`invoke_outlet_with_economy`], and carried into the actor
/// via [`OutletsCommand::SettleOutletEconomy`](crate::context::actor::commands::OutletsCommand::SettleOutletEconomy).
#[derive(Debug)]
pub enum OutletSettleRequest {
    /// Executor succeeded — capture payment + run post-invocation
    /// bookkeeping.
    Capture {
        /// Spawn-generation of the actor instance the reservation was
        /// made against. The settle handler rejects if the live actor's
        /// generation no longer matches.
        generation: u64,
        /// The in-flight economy ticket from Phase 1.
        ticket: OutletEconomyTicket,
    },
    /// Executor failed — void escrow + reverse budget / velocity /
    /// rate-limit.
    Rollback {
        /// Spawn-generation of the actor instance the reservation was
        /// made against. The settle handler rejects if the live actor's
        /// generation no longer matches.
        generation: u64,
        /// The in-flight economy ticket from Phase 1.
        ticket: OutletEconomyTicket,
    },
}

impl OutletSettleRequest {
    /// The spawn-generation the reservation was made against.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        match self {
            Self::Capture { generation, .. } | Self::Rollback { generation, .. } => *generation,
        }
    }

    /// Consume the request and hand back the inner ticket. Used by the
    /// supervisor orchestrator when the actor is unreachable so it can
    /// void the external escrow and consume the ticket locally rather
    /// than dropping it (escrow leak + unbalanced-ticket panic).
    pub fn into_ticket(self) -> OutletEconomyTicket {
        match self {
            Self::Capture { ticket, .. } | Self::Rollback { ticket, .. } => ticket,
        }
    }
}

/// Phase-3 capture outcome returned by the supervisor-supplied `settle`
/// closure to [`invoke_outlet_with_economy`].
#[derive(Debug, Default)]
pub struct OutletSettleOutcome {
    /// Consequences triggered by the invocation.
    pub consequences: Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
    /// Payment receipt when a payment adapter is configured.
    pub payment_receipt: Option<PaymentReceipt>,
    /// Committed action cost for inclusion in the `OutletInvokedEvent`.
    pub cost: Option<Amount>,
}

/// Single Phase-3 settle entry point for the actor
/// [`SettleOutletEconomy`](crate::context::actor::commands::OutletsCommand::SettleOutletEconomy)
/// handler. Dispatches the request to
/// [`settle_outlet_economy_capture`] (success) or [`rollback_outlet_economy`]
/// (failure) on owned state and assembles the [`OutletSettleOutcome`].
///
/// # Errors
///
/// Propagates the capture path's [`ContextError`] on payment-capture
/// failure. The rollback path is infallible.
pub async fn settle_outlet_economy(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    invoker_did: &DID,
    request: OutletSettleRequest,
) -> Result<OutletSettleOutcome, ContextError> {
    // Confused-deputy guard: the reservation was made against a specific
    // actor-instance generation. If this actor's generation differs, the
    // original instance was despawned and a NEW instance respawned for
    // the same `context_id` between reserve and settle (e.g. an import
    // replace). Capturing or refunding against THIS instance's owned
    // budget / velocity / rate-limit would corrupt the wrong context's
    // economy state. Reject without touching this state — void only the
    // EXTERNAL escrow (a real payment hold from the prior instance's
    // reserve) and consume the ticket so it does not leak or trip the
    // unbalanced-Drop guard. `generation` is a Class-C structural field read
    // through the `Deref` to `&PerContextState`.
    if request.generation() != cell.generation {
        let expected = request.generation();
        let actual = cell.generation;
        let ticket = request.into_ticket();
        ticket
            .void_external_and_consume(deps.payment_adapter.as_ref())
            .await;
        return Err(ContextError::ContextNotRegistered(format!(
            "SCP-OUTLET-6088: outlet-economy settle for context '{context_id}' landed on a replaced \
             actor instance (reserved generation {expected}, live generation {actual}); escrow \
             voided, reservation not captured"
        )));
    }

    match request {
        OutletSettleRequest::Capture { ticket, .. } => {
            // Read the committed cost before the ticket is consumed by
            // the capture path so it can be threaded into the event.
            let cost = ticket.deducted_cost;
            // The capture path runs consequence enforcement plus post-invocation
            // participation bookkeeping — it reaches the receive buffer, role
            // state, membership, and the checkpoint counter in ADDITION to the
            // Class-C governance economy fields. `class_c_view()` hands out a
            // `ClassCMut` holding all of those as disjoint field references;
            // `consequence_split()` (inside `settle_outlet_economy_capture`) yields
            // the `ConsequenceStateSplit` shape (consequence-only GROW role view)
            // with NO whole `&mut PerContextState` and NO Class-S reach. Evaluation
            // coalesces
            // through the run loop; the downward-auth outcomes — a
            // consequence-engine capability suspension or an `AssignRole` demotion
            // — populate the caller-owned `downward_auth_obligation` token sink and
            // are persisted fail-closed below (ADR-049 §9, RED-CS3). The sink is
            // owned HERE (not returned by the callee) so the obligation survives the
            // callee's payment-capture error path — a returned token would be
            // stranded/dropped by that early `return Err`, tripping its Drop guard on
            // a path that must still persist or losing the obligation. The token
            // carrier (vs. a `bool`) makes a populated-but-undischarged obligation a
            // Drop-guard PANIC in debug/CI.
            let mut downward_auth_obligation: Option<
                crate::context::actor::class_s::ClassSCommitToken,
            > = None;
            let capture_result = settle_outlet_economy_capture(
                cell.class_c_view(),
                deps,
                context_id,
                invoker_did,
                ticket,
                &mut downward_auth_obligation,
            )
            .await;
            // Fail-closed persist (token `commit`) of an applied downward-auth
            // mutation (keep-direction), run on BOTH the Ok and Err arms: the
            // mutation is already in memory; commit it before acking so a
            // coalesce-window crash cannot silently re-grant the removed authority.
            // `take()` discharges the Drop guard. The view above has been consumed,
            // so the `&mut cell` borrow is released here. ERROR PRECEDENCE: when the
            // capture itself failed, the commit still runs; if the commit ALSO
            // fails, the §9 durability failure (`PersistenceFailed`) is surfaced over
            // the original capture error (durability is the security obligation), and
            // the original capture cause is preserved in its message. When the
            // commit succeeds, the original capture error is surfaced unchanged.
            if let Some(token) = downward_auth_obligation.take()
                && let Err(persist_err) = token.commit(cell, deps, context_id).await
            {
                return Err(match capture_result {
                    Ok(_) => persist_err,
                    Err(capture_err) => ContextError::PersistenceFailed(format!(
                        "{persist_err} (after a outlet-settle payment-capture failure: \
                         {capture_err})"
                    )),
                });
            }
            let (consequences, payment_receipt) = capture_result?;
            Ok(OutletSettleOutcome {
                consequences,
                payment_receipt,
                cost,
            })
        }
        OutletSettleRequest::Rollback { ticket, .. } => {
            rollback_outlet_economy(cell.class_c_view(), deps, ticket).await;
            Ok(OutletSettleOutcome::default())
        }
    }
}

// ---------------------------------------------------------------------------
// §7.3.8 value-caveat counter enforcement (reserve-phase helpers)
// ---------------------------------------------------------------------------

/// Atomically consumes every counter-bearing §7.3.8 caveat for one invocation
/// against the owned Class-S [`CaveatCounters`](crate::trust::caveat_counters::CaveatCounters)
/// record keyed by `ucan_cid`.
///
/// **All-or-nothing.** The consume is applied to a *clone* of the record and
/// written back ONLY if every counter-bearing kind admits — so a rejection on
/// the second/third kind never leaves the first kind's increment stranded in
/// the map. On any [`CounterExhausted`](crate::trust::caveat_counters::CounterExhausted)
/// the map is left unchanged and a mapped [`ContextError`] is returned BEFORE
/// the caller persists (nothing consumed).
///
/// Callers invoke this ONLY inside a `commit_class_s_keep`-family closure
/// (ADR-049 §9): a successful consume is Class-S and MUST ride the fail-closed
/// persist so a coalesce-window crash cannot un-consume it.
///
/// Field→counter map (§7.3.8): `max_calls` = `try_consume(MaxCalls, 1, cap)`;
/// `amount_max_cumulative` = `try_consume(AmountCumulative, action_cost, cap)`;
/// `rate_window` = `try_consume(RateWindow, 0, max, window_secs)`.
fn consume_caveat_counters(
    counters: &mut std::collections::HashMap<String, crate::trust::caveat_counters::CaveatCounters>,
    ucan_cid: &str,
    caveats: &InvocationCaveats,
    action_cost: Amount,
    now_secs: u64,
) -> Result<(), ContextError> {
    let mut record = counters.get(ucan_cid).cloned().unwrap_or_default();

    if let Some(cap) = caveats.max_calls {
        record
            .try_consume(CaveatKind::MaxCalls, 1, cap, 0, now_secs)
            .map_err(|e| counter_exhausted_to_context(ucan_cid, &e))?;
    }
    if let Some(cap) = caveats.amount_max_cumulative {
        record
            .try_consume(
                CaveatKind::AmountCumulative,
                action_cost.value(),
                cap.value(),
                0,
                now_secs,
            )
            .map_err(|e| counter_exhausted_to_context(ucan_cid, &e))?;
    }
    if let Some(rate_window) = caveats.rate_window {
        record
            .try_consume(
                CaveatKind::RateWindow,
                0,
                u64::from(rate_window.max),
                rate_window.window_secs,
                now_secs,
            )
            .map_err(|e| counter_exhausted_to_context(ucan_cid, &e))?;
    }

    // Every counter-bearing kind admitted — commit the fully-updated record.
    counters.insert(ucan_cid.to_owned(), record);
    Ok(())
}

/// Maps a [`CounterExhausted`](crate::trust::caveat_counters::CounterExhausted)
/// onto the Authorization-class [`InvocationError::CaveatViolation`] → typed
/// [`ContextError`], naming the caveat kind that fired (slug) and the owning
/// UCAN CID.
fn counter_exhausted_to_context(
    ucan_cid: &str,
    err: &crate::trust::caveat_counters::CounterExhausted,
) -> ContextError {
    invocation_error_to_context(InvocationError::CaveatViolation {
        slug: err.kind().as_str().to_owned(),
        message: format!("ucan_cid={ucan_cid}: {err}"),
    })
}

/// Maps a synchronous [`CheckInvocationError`](scp_protocol::trust::caveats::CheckInvocationError)
/// onto the Authorization-class [`InvocationError::CaveatViolation`] → typed
/// [`ContextError`], carrying the §5.4.4 / §7.3.8 slug for the rule that fired.
fn check_invocation_error_to_context(
    err: &scp_protocol::trust::caveats::CheckInvocationError,
) -> ContextError {
    invocation_error_to_context(InvocationError::CaveatViolation {
        slug: err.slug().to_owned(),
        message: err.to_string(),
    })
}

fn invocation_error_to_context(err: InvocationError) -> ContextError {
    match err {
        InvocationError::ContextNotActive { current_state } => ContextError::PermissionDenied(
            format!("SCP-OUTLET-6080: context not active: {current_state}"),
        ),
        InvocationError::InvokerNotAuthorized { did, outlet_id } => ContextError::PermissionDenied(
            format!("SCP-OUTLET-6081: invoker {did} lacks OutletCall({outlet_id})"),
        ),
        InvocationError::OutletNotFound { outlet_id } => ContextError::PermissionDenied(format!(
            "SCP-OUTLET-6082: outlet not found: {outlet_id}"
        )),
        InvocationError::InputValidationFailed { message } => ContextError::PermissionDenied(
            format!("SCP-OUTLET-6083: input schema validation failed: {message}"),
        ),
        InvocationError::OutputValidationFailed { message } => ContextError::PermissionDenied(
            format!("SCP-OUTLET-6084: output schema validation failed: {message}"),
        ),
        InvocationError::ExecutionFailed { message } => ContextError::PermissionDenied(format!(
            "SCP-OUTLET-6085: outlet execution failed: {message}"
        )),
        InvocationError::Timeout { timeout_ms } => ContextError::PermissionDenied(format!(
            "SCP-OUTLET-6086: outlet execution timed out after {timeout_ms}ms"
        )),
        InvocationError::Cancelled => ContextError::PermissionDenied(
            "SCP-OUTLET-6087: outlet invocation cancelled".to_owned(),
        ),
        InvocationError::BudgetExceeded {
            did,
            cost,
            remaining,
        } => ContextError::PermissionDenied(format!(
            "SCP-ECON-12010: budget exceeded for {did}: cost {cost}, remaining {remaining}"
        )),
        // §7.3.8 caveat violations (synchronous local check or counter-bearing
        // cap) surface as an Authorization-class permission denial; the slug
        // names the exact caveat rule that fired (§5.4.4 / §7.3.8).
        InvocationError::CaveatViolation { slug, message } => ContextError::PermissionDenied(
            format!("SCP-OUTLET-6110: caveat violation [{slug}]: {message}"),
        ),
        // §5.4.2 Protocol-class violations (SCP-OUT-013): Query cost rule,
        // ReadOnlyInvocation write-deny, and executor kind mismatch all map
        // to the Protocol code family.
        InvocationError::OutletQueryCostViolation { reason } => ContextError::PermissionDenied(
            format!("SCP-OUTLET-6100: Query outlet cost violation (§5.4.2): {reason}"),
        ),
        InvocationError::QueryViolation {
            outlet_id,
            operation,
        } => ContextError::PermissionDenied(format!(
            "SCP-OUTLET-6100: Query outlet {outlet_id} attempted write {operation} through ReadOnlyInvocation (§5.4.2)"
        )),
        InvocationError::KindMismatch { outlet_id, kind } => {
            ContextError::PermissionDenied(format!(
                "SCP-OUTLET-6100: outlet {outlet_id} registered as {kind:?} but executor returned KindMismatch (§5.4.2)"
            ))
        }
        // §5.4.2 / §5.4.4 executor panic (SCP-OUT-028): Execution-class fault.
        InvocationError::HandlerPanic {
            outlet_id,
            panic_message,
        } => ContextError::PermissionDenied(format!(
            "SCP-OUTLET-6130: outlet {outlet_id} handler panicked (execution.handler-panic): {panic_message}"
        )),
        // §5.4.5 "Cross-context economy" (ADR-061): a best-effort cross-context
        // open of a PAID Action outlet is rejected zero-escrow. This is an
        // open-time Economic-class rejection (`SCP-OUTLET-6150`) — NOT a
        // Transport fault — directing the caller to the streaming saga
        // (SCP-OUT-046) for a metered paid cross-context stream.
        InvocationError::CrossContextPaidActionUnsupported { outlet_id } => {
            ContextError::PermissionDenied(format!(
                "SCP-OUTLET-6150: outlet {outlet_id} is a paid Action outlet; the best-effort cross-context bridge is zero-escrow — use the streaming saga (SCP-OUT-046) for a metered paid cross-context stream"
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Streaming open orchestrator helpers (chunk 3e)
// ---------------------------------------------------------------------------

/// Reverse-maps the streaming reserve's [`ContextError`] into the open-time
/// [`OpenStreamRejection`](crate::context::outlets::dispatch::OpenStreamRejection)
/// taxonomy for the [`Supervisor::open_outlet_stream`](crate::context::supervisor::supervisor::Supervisor::open_outlet_stream)
/// orchestrator.
///
/// # Mapping direction (documented per the chunk-3 plan §3a note)
///
/// The streaming reserve ([`reserve_outlet_stream_economy`]) runs INSIDE the
/// per-context actor and can only reply with a `Send` [`ContextError`] across
/// the mailbox, so it encodes its two economic open-time rejections through the
/// LOSSLESS forward direction —
/// [`OpenStreamRejection::to_invocation_error`](crate::context::outlets::dispatch::OpenStreamRejection::to_invocation_error)
/// → [`invocation_error_to_context`] — which embeds the §5.4.4 slug verbatim in
/// the resulting `PermissionDenied` message. This function is the REVERSE map,
/// applied supervisor-side once the reservation error crosses back over the
/// mailbox: it recovers `EscrowOverflow` / `InsufficientFunds` by matching the
/// embedded slug against the SAME `error_codes::SLUG_*` constants the reserve
/// stamped (so the two ends move together if a slug is ever renamed), maps the
/// hard-rate-limit reject to the transport-fault admission slug, and routes
/// every other reserve error (not-a-member, persist failure, transport) through
/// that same transport-fault admission slug — the identical defensive fallback
/// [`open_stream_session`](crate::context::outlets::dispatch::open_stream_session)
/// itself uses for a synchronous failure outside the OUT-034 open taxonomy.
// The `RateLimited` arm and the catch-all fallback intentionally share a body
// (both surface the transport-fault admission slug) but are SEMANTICALLY
// distinct — one is the reserve's hard-rate reject, the other the defensive
// fallback for errors outside the OUT-034 taxonomy. Keep them separate for the
// documented mapping rather than collapsing the meaning into one arm.
#[allow(clippy::match_same_arms)]
pub fn reserve_error_to_open_rejection(
    err: &ContextError,
) -> crate::context::outlets::dispatch::OpenStreamRejection {
    use crate::context::outlets::dispatch::OpenStreamRejection;
    use scp_protocol::context::outlets::error_codes;

    match err {
        ContextError::RateLimited { .. } => OpenStreamRejection::AdmissionRateLimited {
            slug: error_codes::SLUG_TRANSPORT_RATE_LIMITED,
        },
        ContextError::PermissionDenied(msg)
            if msg.contains(error_codes::SLUG_ECONOMIC_ESCROW_OVERFLOW) =>
        {
            OpenStreamRejection::EscrowOverflow
        }
        ContextError::PermissionDenied(msg)
            if msg.contains(error_codes::SLUG_ECONOMIC_INSUFFICIENT_FUNDS) =>
        {
            OpenStreamRejection::InsufficientFunds
        }
        _ => OpenStreamRejection::AdmissionRateLimited {
            slug: error_codes::SLUG_TRANSPORT_RATE_LIMITED,
        },
    }
}

/// The pair returned by [`build_stream_post_input_hook`]: the synchronous
/// §7.3.8 local-check hook and the durable counter reservation committed at the
/// dispatch pump's final open-time gate.
type StreamPostInputBuild = (
    Option<crate::context::outlets::invoke::CaveatPostInputCheck<'static>>,
    Option<crate::context::outlets::dispatch::StreamCounterReservation>,
);

/// Builds the §7.3.8 post-input caveat hook for a streaming open, ENTIRELY
/// inside the runtime, from the streaming open's own inputs — so every bridge
/// gets identical, complete enforcement without supplying any hook. Ported from
/// the reference `ContextManager::build_stream_post_input_hook` onto the actor
/// architecture (the counter store is the actor-owned
/// [`ActorClassSCaveatCounterAdapter`](crate::context::outlets::stream_counter_adapter::ActorClassSCaveatCounterAdapter)).
///
/// A stream validates its input ONCE at open (§5.4.5), so this hook is run
/// exactly once by `open_stream_session` before the pump spawns. It composes
/// the SAME enforcement the non-streaming `invoke` path runs:
///
/// - synchronous local checks — `input_schema`, `amount_max_per_call` (gated
///   against `cost_per_chunk`, the §19.5 per-invocation pricing unit),
///   `allowed_adapters`, `allowed_target_dids`;
/// - the durable counter CAS — `max_calls`, `amount_max_cumulative`,
///   `rate_window` — committed NOT here but at the FINAL open-time gate via the
///   returned [`StreamCounterReservation`](crate::context::outlets::dispatch::StreamCounterReservation)
///   (R4 HIGH-2), so a rejected open burns no counter capacity.
///
/// `negotiated_adapter` and `target_did` are `None` — the streaming open
/// surface (parity with `outlet_invoke`) negotiates neither a payment adapter
/// nor a cross-context target DID.
///
/// Returns:
/// - `Ok((None, None))` when the effective caveat set carries no §7.3.8
///   post-input constraint;
/// - `Ok((Some(hook), reservation))` otherwise (`reservation` is `Some` iff a
///   counter-bearing cap is present AND a counter store is configured);
/// - `Err(CaveatPostInputViolation)` — FAIL CLOSED — when the effective caveats
///   carry a counter-bearing cap but no counter store is available (unreachable
///   in the actor architecture, where the adapter store is always constructible,
///   but retained for a faithful port).
pub fn build_stream_post_input_hook(
    caveats: &InvocationCaveats,
    cost_per_chunk: Amount,
    counter_store: Option<&Arc<dyn crate::trust::CaveatCounterApi>>,
) -> Result<StreamPostInputBuild, crate::context::outlets::dispatch::OpenStreamRejection> {
    use scp_protocol::context::outlets::error_codes;

    if !caveats.requires_post_input_check() {
        return Ok((None, None));
    }

    let reservation = if caveats.has_counter_bearing_caveat() {
        match counter_store {
            Some(store) => Some(
                crate::context::outlets::dispatch::StreamCounterReservation {
                    counter_store: Arc::clone(store),
                    caveats: caveats.clone(),
                },
            ),
            None => {
                return Err(
                    crate::context::outlets::dispatch::OpenStreamRejection::CaveatPostInputViolation {
                        slug: error_codes::SLUG_AUTHORIZATION_DENIED.to_owned(),
                    },
                );
            }
        }
    } else {
        None
    };

    let caveats_owned = caveats.clone();
    let hook: crate::context::outlets::invoke::CaveatPostInputCheck<'static> =
        Box::new(move |input: &serde_json::Value| {
            let caveats = caveats_owned.clone();
            let input = input.clone();
            Box::pin(async move {
                caveats
                    .check_invocation_local(&input, cost_per_chunk, None, None)
                    .map_err(|err| {
                        use scp_protocol::trust::caveats::CheckInvocationError;
                        let message = err.to_string();
                        match err {
                            CheckInvocationError::InputSchemaViolation { .. } => {
                                InvocationError::InputValidationFailed { message }
                            }
                            other => InvocationError::CaveatViolation {
                                slug: other.slug().to_owned(),
                                message,
                            },
                        }
                    })
            })
        });
    Ok((Some(hook), reservation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::actor::state::PerContextState;

    fn test_did() -> DID {
        DID::from("did:test:outlets-rate-limit")
    }

    fn test_admin() -> DID {
        DID::from("did:test:admin")
    }

    #[test]
    fn consume_hard_rate_limit_uses_actor_owned_state() {
        let did = test_did();
        let state = PerContextState::new_for_test_encrypted([9u8; 32], 1, test_admin());
        // The helpers take the field-granular `ClassCMut`; wrap the test state in
        // a `ClassSCell` to construct the view.
        let mut cell = crate::context::actor::class_s::ClassSCell::new(state);

        assert!(try_consume_hard_rate_limit(cell.class_c_view(), &did, 10));
    }

    #[test]
    fn refund_hard_rate_limit_restores_actor_owned_bucket() {
        let did = test_did();
        let state = PerContextState::new_for_test_encrypted([10u8; 32], 1, test_admin());
        let mut cell = crate::context::actor::class_s::ClassSCell::new(state);

        for _ in 0..10 {
            assert!(try_consume_hard_rate_limit(cell.class_c_view(), &did, 10));
        }
        assert!(!try_consume_hard_rate_limit(cell.class_c_view(), &did, 10));
        refund_hard_rate_limit(cell.class_c_view(), &did);
        assert!(try_consume_hard_rate_limit(cell.class_c_view(), &did, 10));
    }

    fn ticket_with_budget(did: &DID) -> OutletEconomyTicket {
        OutletEconomyTicket::new_for_test_no_escrow(did.clone())
    }

    /// `OutletSettleRequest::generation()` reports the reservation's
    /// generation for both variants, and `into_ticket()` hands the inner
    /// ticket back so the orchestrator can reverse it on an unreachable
    /// settle.
    #[test]
    fn settle_request_exposes_generation_and_ticket() {
        let did = test_did();

        let capture = OutletSettleRequest::Capture {
            generation: 42,
            ticket: ticket_with_budget(&did),
        };
        assert_eq!(capture.generation(), 42);
        // Consume the reclaimed ticket so its Drop balance guard does not
        // fire (no escrow ⇒ pure consume).
        capture.into_ticket().consume_abandoning_escrow();

        let rollback = OutletSettleRequest::Rollback {
            generation: 7,
            ticket: ticket_with_budget(&did),
        };
        assert_eq!(rollback.generation(), 7);
        rollback.into_ticket().consume_abandoning_escrow();
    }

    /// The unreachable-actor reversal path
    /// (`OutletEconomyTicket::void_external_and_consume`) must consume the
    /// ticket so its `#[must_use]` Drop balance guard does not fire — a
    /// dropped unbalanced ticket would `debug_assert!`-panic. With no
    /// payment adapter there is no external escrow to void, so this is a
    /// pure consume; reaching the end without a panic is the assertion.
    #[tokio::test]
    async fn void_external_and_consume_consumes_ticket_without_panic() {
        let did = test_did();
        let ticket = ticket_with_budget(&did);
        ticket.void_external_and_consume(None).await;
        // No panic on Drop ⇒ the ticket was consumed.
    }

    /// ADR-049 §9 (RED-CS3): the outlet-settle CAPTURE-FAILURE path must NOT
    /// strand an applied capability suspension on best-effort persistence.
    /// A consequence suspends the invoker in memory BEFORE the fallible payment
    /// capture; if capture then fails, `settle_outlet_economy_capture` returns
    /// `Err` early — so the suspension obligation is carried on a CALLER-OWNED
    /// `&mut Option<ClassSCommitToken>` token sink (not a returned token the `?`
    /// would strand/drop). This test drives the capture path with a FAILING adapter
    /// and a suspending state and asserts the function returns `Err` while the
    /// obligation STILL persists fail-closed (the token survived the error) and the
    /// suspension is retained in memory. Without the fix (a returned token) the
    /// obligation would be stranded by the `?`.
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::similar_names)]
    mod outlet_settle_fail_closed {
        use std::sync::Arc;
        use std::time::Duration;

        use scp_did::DID;
        use scp_protocol::context::params::Capability;
        use scp_protocol::economy::types::{CostSchedule, EconomicPolicy};
        use scp_protocol::trust::consequence::{
            ConsequenceAction, ConsequenceRule, ConsequenceTrigger, EnforcementSeverity,
        };

        use crate::context::actor::class_s::ClassSCell;
        use crate::context::actor::deps::ActorDeps;
        use crate::context::actor::state::PerContextState;
        use crate::context::builder::ContextEventLogProvider;
        use crate::context::providers::MerkleEventLogProvider;
        use crate::economy::adapter::PaymentMetadata;
        use crate::economy::adapter::{
            AdapterCapabilities, PaymentAdapter, PaymentAuthorization, PaymentError,
            PaymentReceipt, RefundConfirmation, VerificationResult,
        };
        use crate::economy::integration::{ActionEnvelope, PreparedAction};
        use scp_protocol::economy::types::{Amount, CurrencyCode, PaidActionType};

        const ADMIN: &str = "did:dht:z6MkAdminOutletSettle";
        const INVOKER: &str = "did:dht:z6MkInvokerOutletSettle";
        const PAYEE: &str = "did:dht:z6MkPayeeOutletSettle";
        const CTX_BYTE: u8 = 0x7c;

        /// A payment adapter whose `capture` ALWAYS fails — the path that drives
        /// `complete_outlet_payment` into its error arm. `verify_authorization`
        /// must succeed first (it runs before capture in `process_paid_action`).
        struct FailingCaptureAdapter;
        impl PaymentAdapter for FailingCaptureAdapter {
            fn adapter_id(&self) -> &'static str {
                "failing-capture"
            }
            fn capabilities(&self) -> AdapterCapabilities {
                AdapterCapabilities {
                    supported_currencies: vec![CurrencyCode::from("USD")],
                    supports_streaming: false,
                    supports_batch_auth: false,
                    supports_single_step: false,
                    min_amount: None,
                    max_amount: None,
                    typical_settlement_ms: 0,
                    requires_facilitator: false,
                }
            }
            async fn authorize(
                &self,
                payer: &DID,
                payee: &DID,
                amount: Amount,
                currency: CurrencyCode,
                _metadata: PaymentMetadata,
            ) -> Result<PaymentAuthorization, PaymentError> {
                Ok(auth(payer, payee, amount, currency))
            }
            async fn verify_authorization(
                &self,
                _auth: &PaymentAuthorization,
            ) -> Result<(), PaymentError> {
                Ok(())
            }
            async fn capture(
                &self,
                _auth: &PaymentAuthorization,
            ) -> Result<PaymentReceipt, PaymentError> {
                Err(PaymentError::AdapterError("induced capture failure".into()))
            }
            async fn void(&self, _auth: &PaymentAuthorization) -> Result<(), PaymentError> {
                Ok(())
            }
            async fn verify(
                &self,
                _receipt: &PaymentReceipt,
            ) -> Result<VerificationResult, PaymentError> {
                Ok(VerificationResult {
                    valid: true,
                    adapter_id: "failing-capture".to_owned(),
                    verified_amount: Amount(0),
                    verified_currency: CurrencyCode::from("USD"),
                    verification_timestamp: 0,
                })
            }
            async fn refund(
                &self,
                _receipt: &PaymentReceipt,
                _amount: Option<Amount>,
            ) -> Result<RefundConfirmation, PaymentError> {
                Ok(RefundConfirmation {
                    refund_id: [0u8; 32],
                    original_receipt_id: [0u8; 32],
                    refunded_amount: Amount(0),
                    currency: CurrencyCode::from("USD"),
                    adapter_proof: vec![],
                })
            }
        }

        fn auth(
            payer: &DID,
            payee: &DID,
            amount: Amount,
            currency: CurrencyCode,
        ) -> PaymentAuthorization {
            PaymentAuthorization {
                auth_id: [9u8; 32],
                payer: payer.clone(),
                payee: payee.clone(),
                amount,
                currency,
                adapter_id: "failing-capture".to_owned(),
                created_at: 1_000_000,
                expires_at: 2_000_000,
                adapter_state: vec![],
            }
        }

        fn paid_policy() -> EconomicPolicy {
            EconomicPolicy {
                locked: false,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: None,
                    per_outlet_call: Some(Amount(50)),
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec!["failing-capture".to_owned()],
                pricing_formula: None,
                payee: DID(PAYEE.to_owned()),
            }
        }

        /// An escrow-bearing ticket whose capture will run (escrow + policy set),
        /// carrying a budget deduction. Consumed by the capture path.
        fn escrow_ticket() -> super::super::OutletEconomyTicket {
            let invoker = DID(INVOKER.to_owned());
            super::super::OutletEconomyTicket::new_for_test_with_escrow(
                invoker.clone(),
                PreparedAction {
                    envelope: ActionEnvelope {
                        actor: invoker.clone(),
                        action_type: PaidActionType::OutletCall,
                        context_id: None,
                        authorization: Some(auth(
                            &invoker,
                            &DID(PAYEE.to_owned()),
                            Amount(50),
                            CurrencyCode::from("USD"),
                        )),
                        payload: Vec::new(),
                    },
                    evaluated_cost: Amount(50),
                },
                paid_policy(),
            )
        }

        async fn build_deps() -> ActorDeps {
            use crate::context::supervisor::supervisor::Supervisor;
            use scp_platform::in_memory::InMemoryStorage;

            let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
                ADMIN.to_owned(),
                std::sync::Arc::new(scp_clock::SystemClock),
            ));
            let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
                Box::new(crate::context::builder::NotConfiguredTransportProvider);
            let event_log: Box<dyn ContextEventLogProvider> =
                Box::new(MerkleEventLogProvider::new());
            let key_resolver: scp_protocol::context::governance::KeyResolver =
                Arc::new(|_, _| None);
            let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
                Arc::new(
                    crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
                        Arc::new(InMemoryStorage::new()),
                    ),
                );
            let clock: Arc<dyn scp_clock::Clock> =
                Arc::new(scp_clock::TestClock::new(1_700_000_000));
            let payment_adapter: Arc<dyn crate::economy::adapter::PaymentAdapterDyn> =
                Arc::new(FailingCaptureAdapter);
            let supervisor = Supervisor::with_providers(
                crypto,
                transport,
                event_log,
                key_resolver,
                Some(Box::new(super::FailOutletPersistence)),
                Some(payment_adapter),
                None,
                Some(clock),
                mls_storage,
            );
            supervisor
                .build_actor_deps(&DID(ADMIN.to_owned()))
                .await
                .expect("build_actor_deps")
        }

        fn seed_state() -> PerContextState {
            let mut state = PerContextState::new_for_test_encrypted(
                [CTX_BYTE; 32],
                1_700_000_000,
                DID(ADMIN.to_owned()),
            );
            state
                .membership
                .add_member(DID(INVOKER.to_owned()), "member".to_owned(), Vec::new());
            state.role_state.members.insert(INVOKER.to_owned());
            state.role_state.member_capabilities.insert(
                INVOKER.to_owned(),
                std::iter::once(Capability::MessagesWrite).collect(),
            );
            // Buffer per-author MessageSent events so a MessageVelocity rule with
            // threshold 1 fires for INVOKER when the settle runs its consequence
            // evaluation (the trigger type is immaterial to the persist path under
            // test — any rule producing a SuspendAccess outcome exercises it).
            for seq in 0..5u64 {
                state.receive_buffer.push(
                    scp_protocol::context::membership::ContextEvent::MessageSent {
                        sender_did: DID(INVOKER.to_owned()),
                        sequence_number: seq,
                        payload: Vec::new(),
                    },
                );
            }
            state.governance.consequence_rules.push(ConsequenceRule {
                trigger: ConsequenceTrigger::MessageVelocity,
                action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess),
                threshold: 1,
                window: Duration::from_hours(1),
            });
            state
        }

        /// The capture-failure path persists the applied suspension fail-closed:
        /// the surfaced error reflects the §9 durability failure (over the
        /// capture error) and the suspension is retained in memory.
        #[tokio::test]
        async fn outlet_settle_capture_failure_persists_suspension_fail_closed() {
            let deps = build_deps().await;
            let mut cell = ClassSCell::new(seed_state());
            let ctx_str = hex::encode([CTX_BYTE; 32]);

            let request = super::super::OutletSettleRequest::Capture {
                generation: cell.generation,
                ticket: escrow_ticket(),
            };
            let result = super::super::settle_outlet_economy(
                &mut cell,
                &deps,
                &ctx_str,
                &DID(INVOKER.to_owned()),
                request,
            )
            .await;

            // Capture failed, but the suspension's fail-closed persist still ran
            // and itself failed → the §9 durability error surfaces (with the
            // capture cause preserved in its message).
            assert!(
                matches!(
                    result,
                    Err(crate::context::ContextError::PersistenceFailed(_))
                ),
                "a outlet-settle whose capture fails AFTER a consequence suspension must \
                 still persist the suspension fail-closed; a failing persist surfaces \
                 PersistenceFailed; got {result:?}"
            );
            let suspended = cell
                .role_state
                .suspended_for(INVOKER)
                .expect("INVOKER must have been suspended by the outlet-rate consequence");
            assert!(
                suspended.contains(&Capability::MessagesWrite),
                "the suspended capability is retained in memory (keep-direction) even \
                 though the payment capture failed"
            );
        }
    }

    /// Persistence whose `persist_context` ALWAYS fails — drives the outlet-settle
    /// fail-closed path. Defined at the `tests` module scope so the nested
    /// `outlet_settle_fail_closed` module can reference it via `super::`.
    struct FailOutletPersistence;
    #[async_trait::async_trait]
    impl crate::context::persistence::ContextPersistence for FailOutletPersistence {
        async fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Err("induced persist failure".into())
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

    /// §7.3.8 value-caveat runtime-enforcement KATs.
    ///
    /// Covers (1) the pure `consume_caveat_counters` helper (all-or-nothing
    /// across kinds, per-`ucan_cid` isolation, Authorization-class slug
    /// mapping); (2) the TOKEN-SOURCE correctness — effective caveats are
    /// sourced from the INVOCATION UCAN's `nb`, never from `spending_ucan`
    /// (`nb: None` on a spending token yields no caveats, which is exactly why
    /// the earlier `spending_ucan`-sourced resolution silently dropped every
    /// caveat); (3) the Class-S snapshot round-trip; and (4) end-to-end
    /// enforcement driven through `reserve_outlet_economy` (the actor-shape
    /// reserve seam where the gate lives) for the free-path counter bounds,
    /// the synchronous local bounds, the sync-before-counter ordering, and the
    /// no-rollback (KEEP-on-persist-failure) guarantee.
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    mod caveat_enforcement {
        use std::collections::HashMap;
        use std::sync::Arc;

        use scp_clock::Clock as _;
        use scp_did::DID;
        use scp_protocol::crypto::ucan::validate::{CaveatResolver, TokenNbCaveatResolver};
        use scp_protocol::crypto::ucan::{UcanHeader, UcanPayload, UcanToken};
        use scp_protocol::economy::types::Amount;
        use scp_protocol::trust::caveats::{InvocationCaveats, RateWindow};

        use super::super::InvocationCaveatBinding;
        use crate::context::ContextError;
        use crate::context::ContextState;
        use crate::context::actor::class_s::ClassSCell;
        use crate::context::actor::deps::ActorDeps;
        use crate::context::actor::state::PerContextState;
        use crate::trust::caveat_counters::CaveatCounters;

        const INVOKER: &str = "did:dht:z6MkCaveatInvoker";
        const CTX_BYTE: u8 = 0xCA;

        fn ctx_key() -> String {
            hex::encode([CTX_BYTE; 32])
        }

        fn max_calls_caveats(cap: u64) -> InvocationCaveats {
            let mut c = InvocationCaveats::empty();
            c.max_calls = Some(cap);
            c
        }

        // -------------------------------------------------------------------
        // Pure `consume_caveat_counters` helper
        // -------------------------------------------------------------------

        /// All-or-nothing across counter kinds: a consume that ADMITS on
        /// `max_calls` but REJECTS on `amount_max_cumulative` must leave the map
        /// UNCHANGED — the earlier kind's increment is never stranded (the
        /// helper mutates a clone and writes back only on full success).
        #[test]
        fn consume_caveat_counters_is_all_or_nothing_across_kinds() {
            let cid = "cid-aon";
            let mut counters: HashMap<String, CaveatCounters> = HashMap::new();
            counters.insert(
                cid.to_owned(),
                CaveatCounters {
                    amount_cumulative_used: 3,
                    ..Default::default()
                },
            );
            let mut caveats = InvocationCaveats::empty();
            caveats.max_calls = Some(5); // admits (0 -> 1)
            caveats.amount_max_cumulative = Some(Amount::new(3)); // 3 + 1 > 3 rejects
            let err = super::super::consume_caveat_counters(
                &mut counters,
                cid,
                &caveats,
                Amount::new(1),
                1_000,
            )
            .expect_err("amount cap already met — the consume must reject");
            assert!(
                format!("{err}").contains("amountMaxCumulative"),
                "must reject on the amount kind: {err}"
            );
            let rec = &counters[cid];
            assert_eq!(
                rec.max_calls_used, 0,
                "max_calls must NOT be incremented when a later kind rejects (all-or-nothing)"
            );
            assert_eq!(
                rec.amount_cumulative_used, 3,
                "the amount counter must be unchanged on reject"
            );
        }

        /// Counters are keyed by `ucan_cid`: exhausting one delegation's cap
        /// leaves every other delegation's counters untouched.
        #[test]
        fn consume_caveat_counters_isolates_per_ucan_cid() {
            let mut counters: HashMap<String, CaveatCounters> = HashMap::new();
            let caveats = max_calls_caveats(1);
            super::super::consume_caveat_counters(
                &mut counters,
                "cid-a",
                &caveats,
                Amount::new(0),
                1,
            )
            .expect("cid-a first admits");
            super::super::consume_caveat_counters(
                &mut counters,
                "cid-b",
                &caveats,
                Amount::new(0),
                1,
            )
            .expect("cid-b is independent and admits");
            assert_eq!(counters["cid-a"].max_calls_used, 1);
            assert_eq!(counters["cid-b"].max_calls_used, 1);
            super::super::consume_caveat_counters(
                &mut counters,
                "cid-a",
                &caveats,
                Amount::new(0),
                1,
            )
            .expect_err("cid-a second exceeds its cap");
            assert_eq!(
                counters["cid-b"].max_calls_used, 1,
                "cid-b must be unaffected by cid-a's exhaustion"
            );
        }

        /// A `CounterExhausted` maps to the Authorization-class caveat-violation
        /// code (`SCP-OUTLET-6110`) carrying the §7.3.8 slug of the kind that
        /// fired.
        #[test]
        fn consume_caveat_counters_maps_exhaustion_to_authorization_slug() {
            let mut counters: HashMap<String, CaveatCounters> = HashMap::new();
            let caveats = max_calls_caveats(1);
            super::super::consume_caveat_counters(
                &mut counters,
                "cid",
                &caveats,
                Amount::new(0),
                1,
            )
            .expect("first admits");
            let err = super::super::consume_caveat_counters(
                &mut counters,
                "cid",
                &caveats,
                Amount::new(0),
                1,
            )
            .expect_err("second exceeds cap");
            let msg = format!("{err}");
            assert!(
                msg.contains("SCP-OUTLET-6110") && msg.contains("maxCalls"),
                "exhaustion must map to the Authorization code + kind slug: {msg}"
            );
        }

        // -------------------------------------------------------------------
        // Token-source correctness (resolver)
        // -------------------------------------------------------------------

        fn ucan_with_nb(nb: Option<InvocationCaveats>) -> UcanToken {
            UcanToken {
                header: UcanHeader::new(),
                payload: UcanPayload {
                    iss: INVOKER.to_owned(),
                    aud: "did:dht:z6MkCaveatCtx".to_owned(),
                    exp: 9_999_999_999,
                    nbf: None,
                    nnc: "0-00000000000000000000000000000000".to_owned(),
                    att: vec![],
                    prf: vec![],
                    fct: None,
                    nb,
                },
                signature: vec![],
                encoded: "header.payload.sig".to_owned(),
            }
        }

        /// THE token-source KAT. The value-caveats live in the INVOCATION UCAN's
        /// `nb`; a spending UCAN (§19.5 economy token) carries `nb: None`. The
        /// resolver the bridges use reads exactly the `nb` field, so the
        /// invocation token IS the caveat source and a spending token yields
        /// NONE — the precise reason the prior `spending_ucan`-sourced
        /// resolution left §7.3.8 caveats entirely inert.
        #[test]
        fn caveats_sourced_from_invocation_nb_never_from_spending_ucan() {
            let caveats = max_calls_caveats(2);
            let invocation = ucan_with_nb(Some(caveats.clone()));
            let spending = ucan_with_nb(None);
            assert_eq!(
                TokenNbCaveatResolver.resolve_caveats(&invocation),
                Some(caveats),
                "the invocation UCAN's nb must resolve to its caveats"
            );
            assert_eq!(
                TokenNbCaveatResolver.resolve_caveats(&spending),
                None,
                "a spending UCAN (nb None) must resolve to NO caveats — never a source"
            );
        }

        // -------------------------------------------------------------------
        // Class-S snapshot round-trip
        // -------------------------------------------------------------------

        /// Consumed counters survive a Class-S snapshot → clear → restore cycle
        /// (the on-disk `ContextSnapshot` mirror rehydrates them after a crash).
        #[test]
        fn caveat_counters_survive_class_s_snapshot_round_trip() {
            let mut state = active_state();
            state.class_s.caveat_counters.insert(
                "cid-snap".to_owned(),
                CaveatCounters {
                    max_calls_used: 3,
                    amount_cumulative_used: 42,
                    rate_window_timestamps: vec![1, 2, 3],
                },
            );
            let snap = state.class_s.snapshot();
            state.class_s.caveat_counters.clear();
            assert!(state.class_s.caveat_counters.is_empty());
            state.class_s.restore(snap);
            let rec = &state.class_s.caveat_counters["cid-snap"];
            assert_eq!(rec.max_calls_used, 3);
            assert_eq!(rec.amount_cumulative_used, 42);
            assert_eq!(rec.rate_window_timestamps, vec![1, 2, 3]);
        }

        /// Fix-D: streaming reservation recovery records survive a Class-S
        /// snapshot → clear → restore cycle (the ADR-049 §9 mirror rehydrates
        /// them after a crash so the reconcile sweep can release the stranded
        /// escrow hold + cumulative counter reserve).
        #[test]
        fn stream_reservations_survive_class_s_snapshot_round_trip() {
            use crate::context::outlets::invoke::StreamReservationRecord;

            let expected = StreamReservationRecord {
                invoker_did: scp_did::DID::from("did:key:snap-invoker"),
                ucan_cid: "cid-open".to_owned(),
                cost_per_chunk: Amount::new(9),
                amount_cumulative_reserved: 270,
                reserved_escrow: Amount::new(180),
                generation: 2,
            };
            let mut state = active_state();
            state
                .class_s
                .stream_reservations
                .insert("req-snap".to_owned(), expected.clone());

            let snap = state.class_s.snapshot();
            state.class_s.stream_reservations.clear();
            assert!(state.class_s.stream_reservations.is_empty());
            state.class_s.restore(snap);
            assert_eq!(state.class_s.stream_reservations["req-snap"], expected);
        }

        // -------------------------------------------------------------------
        // End-to-end enforcement via `reserve_outlet_economy`
        // -------------------------------------------------------------------

        /// Persistence double whose `persist_context` always SUCCEEDS — the
        /// happy path for the counter consume's fail-closed persist.
        struct OkPersistence;
        #[async_trait::async_trait]
        impl crate::context::persistence::ContextPersistence for OkPersistence {
            async fn persist_context(
                &self,
                _: &str,
                _: &crate::context::state::ContextSnapshot,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

        async fn build_deps(
            persistence: Box<dyn crate::context::persistence::ContextPersistence>,
        ) -> ActorDeps {
            use crate::context::supervisor::supervisor::Supervisor;
            use scp_platform::in_memory::InMemoryStorage;

            let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
                INVOKER.to_owned(),
                Arc::new(scp_clock::SystemClock),
            ));
            let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
                Box::new(crate::context::builder::NotConfiguredTransportProvider);
            let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
                Box::new(crate::context::providers::MerkleEventLogProvider::new());
            let key_resolver: scp_protocol::context::governance::KeyResolver =
                Arc::new(|_, _| None);
            let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
                Arc::new(
                    crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
                        Arc::new(InMemoryStorage::new()),
                    ),
                );
            let clock: Arc<dyn scp_clock::Clock> =
                Arc::new(scp_clock::TestClock::new(1_700_000_000));
            // No payment adapter: a free outlet (action_cost == 0) whose
            // counter consume rides the dedicated free-path commit_class_s_keep.
            let supervisor = Supervisor::with_providers(
                crypto,
                transport,
                event_log,
                key_resolver,
                Some(persistence),
                None,
                None,
                Some(clock),
                mls_storage,
            );
            supervisor
                .build_actor_deps(&DID(INVOKER.to_owned()))
                .await
                .expect("build_actor_deps")
        }

        fn active_state() -> PerContextState {
            let state = PerContextState::new_for_test_encrypted(
                [CTX_BYTE; 32],
                1_700_000_000,
                DID(INVOKER.to_owned()),
            );
            state
                .handle
                .transition_to(&ContextState::Active)
                .expect("transition to Active");
            state
        }

        /// Drive one reserve step. On success, consume the returned ticket (its
        /// `#[must_use]` Drop balance guard would otherwise fire); the counter
        /// consume already committed as Class-S BEFORE the ticket was built, and
        /// the void does not touch `caveat_counters`.
        async fn reserve_step(
            cell: &mut ClassSCell,
            deps: &ActorDeps,
            caveats: Option<&InvocationCaveats>,
            cid: Option<&str>,
            input: &serde_json::Value,
            now: u64,
        ) -> Result<(), ContextError> {
            // Mirror the bridge: caveats + cid are minted together from the
            // ONE invocation UCAN, so they bundle into one binding or neither.
            let binding = caveats.zip(cid).map(|(c, id)| InvocationCaveatBinding {
                caveats: c.clone(),
                ucan_cid: id.to_owned(),
            });
            let reservation = super::super::reserve_outlet_economy(
                cell,
                deps,
                &ctx_key(),
                &DID(INVOKER.to_owned()),
                None,
                binding.as_ref(),
                input,
                now,
            )
            .await?;
            reservation.ticket.void_external_and_consume(None).await;
            Ok(())
        }

        /// `max_calls` (counter bound): the first invocation admits and consumes
        /// the single slot; the second is rejected as `maxCalls`. Sourced from
        /// the `effective_caveats` param — exactly what the bridge derives from
        /// the invocation UCAN's `nb`.
        #[tokio::test]
        async fn reserve_free_path_enforces_max_calls() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut cell = ClassSCell::new(active_state());
            let caveats = max_calls_caveats(1);
            let cid = "cid-mc";
            let input = serde_json::json!({});
            reserve_step(
                &mut cell,
                &deps,
                Some(&caveats),
                Some(cid),
                &input,
                1_700_000_100,
            )
            .await
            .expect("first invocation within max_calls=1 must admit");
            let err = reserve_step(
                &mut cell,
                &deps,
                Some(&caveats),
                Some(cid),
                &input,
                1_700_000_101,
            )
            .await
            .expect_err("second invocation must exceed max_calls=1");
            assert!(
                format!("{err}").contains("maxCalls"),
                "reject must name the maxCalls caveat: {err}"
            );
            assert_eq!(
                cell.class_s.caveat_counters[cid].max_calls_used, 1,
                "exactly one call consumed"
            );
        }

        /// TOKEN-SOURCE at the reserve seam: the reserve enforces the
        /// `effective_caveats` param and consults NO other token's `nb`. With
        /// caveats present the cap is enforced; with `effective_caveats == None`
        /// (the invocation UCAN carried no `nb`) NO cap exists and every call
        /// admits, creating no counter record.
        #[tokio::test]
        async fn reserve_enforces_effective_caveats_param_not_spending_nb() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let input = serde_json::json!({});

            let mut cell = ClassSCell::new(active_state());
            let caveats = max_calls_caveats(1);
            reserve_step(
                &mut cell,
                &deps,
                Some(&caveats),
                Some("cid-src"),
                &input,
                1_700_000_100,
            )
            .await
            .expect("admit");
            reserve_step(
                &mut cell,
                &deps,
                Some(&caveats),
                Some("cid-src"),
                &input,
                1_700_000_101,
            )
            .await
            .expect_err("cap enforced when sourced from the invocation caveats");

            let mut cell2 = ClassSCell::new(active_state());
            for i in 0..3 {
                reserve_step(&mut cell2, &deps, None, None, &input, 1_700_000_200 + i)
                    .await
                    .expect("no invocation caveats => always admit");
            }
            assert!(
                cell2.class_s.caveat_counters.is_empty(),
                "no caveats resolved => no counter record — reserve never fabricates caveats"
            );
        }

        /// Sync-first ordering: a bad `input_schema` is rejected by the
        /// synchronous local check BEFORE the `max_calls` counter is touched, so
        /// the single slot survives for a subsequent conforming call.
        #[tokio::test]
        async fn reserve_sync_check_precedes_counter_consume() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut cell = ClassSCell::new(active_state());
            let mut caveats = InvocationCaveats::empty();
            caveats.max_calls = Some(1);
            caveats.input_schema = Some(serde_json::json!({
                "type": "object",
                "required": ["x"],
                "properties": {"x": {"type": "string"}}
            }));
            let cid = "cid-order";
            let err = reserve_step(
                &mut cell,
                &deps,
                Some(&caveats),
                Some(cid),
                &serde_json::json!({}),
                1_700_000_100,
            )
            .await
            .expect_err("input missing required 'x' must reject on the schema");
            assert!(
                format!("{err}").contains("input"),
                "must reject on the input_schema sync check: {err}"
            );
            assert!(
                !cell.class_s.caveat_counters.contains_key(cid),
                "a sync-rejected call must NOT create or consume a counter record"
            );
            reserve_step(
                &mut cell,
                &deps,
                Some(&caveats),
                Some(cid),
                &serde_json::json!({"x": "ok"}),
                1_700_000_101,
            )
            .await
            .expect(
                "conforming input within max_calls=1 must admit — the rejected call spent nothing",
            );
            assert_eq!(
                cell.class_s.caveat_counters[cid].max_calls_used, 1,
                "the single slot was consumed only by the conforming call"
            );
        }

        /// `rate_window` (counter bound): admits until the window cap, then
        /// rejects as `rateWindow`.
        #[tokio::test]
        async fn reserve_free_path_enforces_rate_window() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut cell = ClassSCell::new(active_state());
            let mut caveats = InvocationCaveats::empty();
            caveats.rate_window = Some(RateWindow {
                max: 1,
                window_secs: 100,
            });
            let cid = "cid-rw";
            let input = serde_json::json!({});
            reserve_step(
                &mut cell,
                &deps,
                Some(&caveats),
                Some(cid),
                &input,
                1_700_000_100,
            )
            .await
            .expect("first within the rate window admits");
            let err = reserve_step(
                &mut cell,
                &deps,
                Some(&caveats),
                Some(cid),
                &input,
                1_700_000_101,
            )
            .await
            .expect_err("second within the same window exceeds max=1");
            assert!(
                format!("{err}").contains("rateWindow"),
                "reject must name the rateWindow caveat: {err}"
            );
        }

        /// `allowed_target_dids` (sync bound): single-shot same-context passes
        /// `target_did = None`, so a populated allow-list is unsatisfiable and
        /// fail-closed rejects — touching no counter.
        #[tokio::test]
        async fn reserve_sync_rejects_disallowed_target_did() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut cell = ClassSCell::new(active_state());
            let mut caveats = InvocationCaveats::empty();
            caveats.allowed_target_dids = Some(vec![DID::from("did:dht:z6MkOtherTarget")]);
            let err = reserve_step(
                &mut cell,
                &deps,
                Some(&caveats),
                Some("cid-target"),
                &serde_json::json!({}),
                1_700_000_100,
            )
            .await
            .expect_err("populated allowed_target_dids must reject a same-context call");
            assert!(
                format!("{err}").contains("SCP-OUTLET-6110"),
                "target-DID reject must surface a caveat violation: {err}"
            );
            assert!(
                cell.class_s.caveat_counters.is_empty(),
                "a sync reject touches no counter"
            );
        }

        /// `allowed_adapters` (sync bound): the free path negotiates no payment
        /// adapter, so a populated adapter allow-list is unsatisfiable and
        /// fail-closed rejects.
        #[tokio::test]
        async fn reserve_sync_rejects_disallowed_adapter() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut cell = ClassSCell::new(active_state());
            let mut caveats = InvocationCaveats::empty();
            caveats.allowed_adapters = Some(vec!["x402".to_owned()]);
            let err = reserve_step(
                &mut cell,
                &deps,
                Some(&caveats),
                Some("cid-adapter"),
                &serde_json::json!({}),
                1_700_000_100,
            )
            .await
            .expect_err("populated allowed_adapters must reject when no adapter is negotiated");
            assert!(
                format!("{err}").contains("SCP-OUTLET-6110"),
                "adapter reject must surface a caveat violation: {err}"
            );
        }

        /// No-rollback: the free-path counter consume rides a fail-closed
        /// `commit_class_s_keep`. A persist FAILURE surfaces an error to the
        /// caller, but the consumed cap is KEPT in memory (a consumed cap must
        /// never un-consume — ADR-049 §9). No ticket is built on this path, so
        /// there is no Drop-guard obligation.
        #[tokio::test]
        async fn reserve_counter_consume_is_kept_on_persist_failure() {
            let deps = build_deps(Box::new(super::FailOutletPersistence)).await;
            let mut cell = ClassSCell::new(active_state());
            let caveats = max_calls_caveats(1);
            let cid = "cid-keep";
            let err = reserve_step(
                &mut cell,
                &deps,
                Some(&caveats),
                Some(cid),
                &serde_json::json!({}),
                1_700_000_100,
            )
            .await
            .expect_err("a persist failure must surface fail-closed");
            assert!(
                format!("{err}").to_lowercase().contains("persist"),
                "expected a fail-closed persistence error: {err}"
            );
            assert_eq!(
                cell.class_s.caveat_counters[cid].max_calls_used, 1,
                "the consumed cap must be KEPT across the persist failure (no un-consume)"
            );
        }

        // -------------------------------------------------------------------
        // End-to-end enforcement via `reserve_outlet_economy` — PAID path
        // -------------------------------------------------------------------
        //
        // The free-path tests above drive the counter consume through the
        // dedicated `commit_class_s_keep` (outlets_helpers.rs ~919). The PAID
        // path folds the counter consume into `commit_class_s_keep_compensating`
        // (outlets_helpers.rs ~842-863) — a different combinator with its own
        // budget/velocity compensation. This block exercises THAT path with a
        // real `action_cost > 0` and a VALID signed spending UCAN.

        /// Deterministic Ed25519 seed from a DID (mirrors the outlet-economy
        /// wiring test's `did_to_seed` so signing and verification agree).
        fn did_to_seed(did: &DID) -> [u8; 32] {
            let mut s = [0u8; 32];
            for (i, b) in did.as_ref().as_bytes().iter().enumerate() {
                s[i % 32] ^= *b;
            }
            s
        }

        /// Signing key for `did` — the private half of what `mock_key_resolver`
        /// returns, so a spending UCAN issued by `did` verifies against it.
        fn signing_key_for_did(did: &DID) -> ed25519_dalek::SigningKey {
            ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did))
        }

        /// Key resolver that returns the verifying key `signing_key_for_did`
        /// signs with. Wired into the paid deps so
        /// `validate_spending_ucan_or_error` (called inside
        /// `commit_class_s_keep_compensating`) can resolve the spending-UCAN
        /// issuer DID → key and verify the Ed25519 signature. The free-path
        /// `build_deps` uses a `|_, _| None` resolver, which would fail signature
        /// verification — a paid test MUST supply real keys.
        fn mock_key_resolver() -> scp_protocol::context::governance::KeyResolver {
            Arc::new(|did: &DID, _kid: scp_did::SigningKeyId| {
                Some(ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did)).verifying_key())
            })
        }

        /// A paid economic policy: a per-outlet-call cost > 0 makes
        /// `economy_pre_check` return `action_cost > 0`, routing the reserve
        /// through the PAID `commit_class_s_keep_compensating` branch.
        fn paid_policy() -> scp_protocol::economy::types::EconomicPolicy {
            use scp_protocol::economy::types::{CostSchedule, CurrencyCode, EconomicPolicy};
            EconomicPolicy {
                locked: false,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: None,
                    per_outlet_call: Some(Amount::new(5)),
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec![],
                pricing_formula: None,
                payee: DID::from("did:key:caveat-payee"),
            }
        }

        /// Fully-signed spending UCAN bound to `actor_did` (iss == aud), valid at
        /// wall-clock time. Mirrors the outlet-economy wiring test's
        /// `signed_spending_ucan_for`: `kid: "#agent"` + `scp_key_scope: "#agent"`
        /// fact, a `scp:spending:*` attenuation, a capability that comfortably
        /// covers the per-call cost, and a FRESH single-use nonce (each call
        /// generates a new one). The token is signed over the base64url
        /// `header.payload` and `encoded` carries the full three-segment JWT so
        /// `verify_signature` reconstructs the signing input.
        fn signed_spending_ucan_for(actor_did: &DID) -> UcanToken {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use scp_protocol::crypto::ucan::nonce::generate_nonce;
            use scp_protocol::crypto::ucan::spending::{
                Amount as SpendAmount, CurrencyCode as SpendCurrency, SpendingCapability,
            };
            use scp_protocol::crypto::ucan::{Attenuation, UcanHeader};

            let cap = SpendingCapability {
                max_per_action: SpendAmount(u64::MAX),
                max_total: SpendAmount(u64::MAX),
                currency: SpendCurrency::from_code("USD").expect("USD is a valid code"),
                time_window: std::time::Duration::from_hours(1),
                allowed_adapters: vec![],
            };
            let mut fct = serde_json::Map::new();
            fct.insert(
                "spending_capability".to_owned(),
                cap.to_fact_value()
                    .expect("capability serializes to a fact value"),
            );
            fct.insert(
                "scp_key_scope".to_owned(),
                serde_json::Value::String("#agent".to_owned()),
            );

            // Wall-clock times: the paid deps use a `SystemClock`, and the
            // in-state spending-nonce tracker (built by `new_for_test_encrypted`)
            // also uses `SystemClock`, so expiry + nonce-freshness both validate
            // against real time.
            let now = scp_clock::SystemClock.now_secs();
            let header = UcanHeader::with_kid("#agent".to_owned());
            let payload = UcanPayload {
                iss: actor_did.as_ref().to_owned(),
                aud: actor_did.as_ref().to_owned(),
                exp: now + 3600,
                nbf: Some(now.saturating_sub(60)),
                nnc: generate_nonce(&scp_clock::SystemClock),
                att: vec![Attenuation {
                    with: "scp:spending:*".to_owned(),
                    can: "spend".to_owned(),
                }],
                prf: vec![],
                fct: Some(serde_json::Value::Object(fct)),
                nb: None,
            };

            let header_json = serde_json::to_vec(&header).expect("header serializes");
            let payload_json = serde_json::to_vec(&payload).expect("payload serializes");
            let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
            let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
            let signing_input = format!("{header_b64}.{payload_b64}");
            let signing_key = signing_key_for_did(actor_did);
            let signature = ed25519_dalek::Signer::sign(&signing_key, signing_input.as_bytes());
            let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
            let encoded = format!("{signing_input}.{sig_b64}");

            UcanToken {
                header,
                payload,
                signature: signature.to_bytes().to_vec(),
                encoded,
            }
        }

        /// Paid deps: a real-time `SystemClock` (so the spending UCAN's expiry
        /// and nonce freshness validate against the same wall clock the in-state
        /// nonce tracker uses) and a `mock_key_resolver` that resolves the
        /// spending-UCAN issuer DID → verifying key. No payment adapter is
        /// configured: the reserve's escrow authorization only runs when BOTH a
        /// policy AND an adapter are present (`outlets_helpers.rs` ~948), so with no
        /// adapter the escrow is skipped and the PAID
        /// `commit_class_s_keep_compensating` (spending-nonce + budget + counter
        /// consume) is exactly the path under test. This matches the committed
        /// outlet-economy wiring reference, whose paid happy path also configures
        /// no adapter and asserts `payment_receipt.is_none()`.
        async fn build_deps_paid(
            persistence: Box<dyn crate::context::persistence::ContextPersistence>,
        ) -> ActorDeps {
            use crate::context::supervisor::supervisor::Supervisor;
            use scp_platform::in_memory::InMemoryStorage;

            let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
                INVOKER.to_owned(),
                Arc::new(scp_clock::SystemClock),
            ));
            let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
                Box::new(crate::context::builder::NotConfiguredTransportProvider);
            let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
                Box::new(crate::context::providers::MerkleEventLogProvider::new());
            let key_resolver = mock_key_resolver();
            let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
                Arc::new(
                    crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
                        Arc::new(InMemoryStorage::new()),
                    ),
                );
            let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::SystemClock);
            let supervisor = Supervisor::with_providers(
                crypto,
                transport,
                event_log,
                key_resolver,
                Some(persistence),
                None,
                None,
                Some(clock),
                mls_storage,
            );
            supervisor
                .build_actor_deps(&DID(INVOKER.to_owned()))
                .await
                .expect("build_actor_deps")
        }

        /// `active_state()` plus a paid economic policy and a funded budget for
        /// INVOKER, so `economy_pre_check` yields `action_cost > 0` and
        /// `record_spend` succeeds on the paid branch.
        fn paid_active_state() -> PerContextState {
            let mut state = active_state();
            state.governance.economic_policy = Some(paid_policy());
            state
                .governance
                .budget_tracker
                .grant(&DID(INVOKER.to_owned()), Amount::new(1_000));
            state
        }

        /// Drive one PAID reserve step: thread a signed spending UCAN into the
        /// `spending_ucan` slot (the free-path `reserve_step` passes `None`
        /// there) alongside the counter-bearing caveat binding. On success,
        /// consume the returned ticket (its `#[must_use]` Drop balance guard
        /// would otherwise fire); with no payment adapter there is no escrow to
        /// void, and the counter consume already committed as Class-S before the
        /// ticket was built.
        async fn paid_reserve_step(
            cell: &mut ClassSCell,
            deps: &ActorDeps,
            spending: &UcanToken,
            caveats: &InvocationCaveats,
            cid: &str,
            input: &serde_json::Value,
            now: u64,
        ) -> Result<(), ContextError> {
            let binding = InvocationCaveatBinding {
                caveats: caveats.clone(),
                ucan_cid: cid.to_owned(),
            };
            let reservation = super::super::reserve_outlet_economy(
                cell,
                deps,
                &ctx_key(),
                &DID(INVOKER.to_owned()),
                Some(spending),
                Some(&binding),
                input,
                now,
            )
            .await?;
            reservation.ticket.void_external_and_consume(None).await;
            Ok(())
        }

        /// PAID-path caveat KAT (§7.3.8). Drives `reserve_outlet_economy` on the
        /// PAID branch (`action_cost > 0` + a VALID signed spending UCAN) and
        /// proves the counter consume folded into
        /// `commit_class_s_keep_compensating` (outlets_helpers.rs ~842-863) is
        /// live on that path:
        ///
        /// (a) a `max_calls = 1` caveat IS consumed on the paid path — after one
        ///     successful paid reserve the owned Class-S counter reads
        ///     `max_calls_used == 1`, and a SECOND paid reserve (same cid, a FRESH
        ///     spending UCAN) rejects naming `maxCalls`.
        ///
        /// (b) On the `CounterExhausted` reject the paid-path compensation runs
        ///     (outlets_helpers.rs ~852-862): the just-charged budget is rolled
        ///     back inline while the spending nonce stays consumed (the closure
        ///     returns Err AFTER `commit_spending_ucan_nonce`). The governance
        ///     budget tracker is `pub(crate)` and thus observable from this test
        ///     module, so the rollback is asserted directly — the invoker's
        ///     remaining budget after the REJECTED second call equals its
        ///     remaining budget after the first (ADMITTED) call, so only the one
        ///     admitted charge stuck. The nonce's single-use is proven separately:
        ///     re-presenting the first UCAN rejects on replay INSIDE
        ///     `validate_spending_ucan_or_error` (which runs before the counter
        ///     consume), so each paid reserve genuinely needs a distinct fresh
        ///     spending UCAN.
        #[tokio::test]
        async fn reserve_paid_path_enforces_max_calls_and_compensates() {
            let deps = build_deps_paid(Box::new(OkPersistence)).await;
            let mut cell = ClassSCell::new(paid_active_state());
            let invoker = DID(INVOKER.to_owned());
            let caveats = max_calls_caveats(1);
            let cid = "cid-paid-mc";
            let input = serde_json::json!({});
            // `now` here feeds the velocity / hard-rate / caveat bookkeeping; the
            // spending UCAN's own expiry + nonce validate against the deps'
            // `SystemClock`, independent of this value.
            let now = scp_clock::SystemClock.now_secs();

            let remaining_start = cell.governance.budget_tracker.remaining(&invoker).0;
            assert_eq!(remaining_start, 1_000, "seeded invoker budget");

            // FIRST paid reserve: valid signed UCAN, action_cost = 5 (> 0 → paid
            // branch). The counter consume in `commit_class_s_keep_compensating`
            // admits and consumes the single max_calls slot.
            let spending1 = signed_spending_ucan_for(&invoker);
            paid_reserve_step(&mut cell, &deps, &spending1, &caveats, cid, &input, now)
                .await
                .expect("first paid reserve within max_calls=1 must admit on the PAID branch");
            assert_eq!(
                cell.class_s.caveat_counters[cid].max_calls_used, 1,
                "the PAID path consumed exactly one max_calls slot"
            );
            let remaining_after_first = cell.governance.budget_tracker.remaining(&invoker).0;
            assert_eq!(
                remaining_after_first,
                remaining_start - 5,
                "the first paid reserve charged the per_outlet_call cost (5) exactly once"
            );

            // SECOND paid reserve: a DISTINCT fresh spending UCAN (single-use
            // nonce — reusing spending1 would reject on nonce replay, not the
            // caveat). The max_calls slot is exhausted, so the counter consume —
            // the LAST mutation in the paid closure — rejects with
            // CounterExhausted (maxCalls).
            let spending2 = signed_spending_ucan_for(&invoker);
            let err = paid_reserve_step(&mut cell, &deps, &spending2, &caveats, cid, &input, now)
                .await
                .expect_err("second paid reserve must exceed max_calls=1");
            assert!(
                format!("{err}").contains("maxCalls"),
                "the PAID-path reject must name the maxCalls caveat: {err}"
            );

            // (b) Compensation ran: the CounterExhausted reject rolled the
            // just-charged budget back inline (outlets_helpers.rs ~852-862), so
            // the net remaining budget is unchanged from after the first
            // (admitted) charge — the rejected call left NO budget stuck.
            let remaining_after_second = cell.governance.budget_tracker.remaining(&invoker).0;
            assert_eq!(
                remaining_after_second, remaining_after_first,
                "the rejected paid reserve rolled back its budget charge (compensation) — \
                 only the first, admitted call's charge stuck"
            );
            assert_eq!(
                cell.class_s.caveat_counters[cid].max_calls_used, 1,
                "a rejected paid reserve does not advance the exhausted counter past its cap"
            );

            // Single-use nonce: re-presenting the FIRST spending UCAN (its nonce
            // was committed on the admitted call) rejects on replay INSIDE
            // `validate_spending_ucan_or_error`, which runs BEFORE the counter
            // consume in the paid closure — proving every paid reserve needs a
            // distinct fresh spending UCAN, never a replay.
            let err_replay =
                paid_reserve_step(&mut cell, &deps, &spending1, &caveats, cid, &input, now)
                    .await
                    .expect_err(
                        "re-presenting a consumed spending UCAN must reject on nonce replay",
                    );
            let replay_msg = format!("{err_replay}").to_lowercase();
            assert!(
                replay_msg.contains("scp-econ-12065")
                    || replay_msg.contains("nonce")
                    || replay_msg.contains("replay"),
                "a reused spending-UCAN nonce must reject inside spending validation \
                 (before the counter): {err_replay}"
            );
        }

        /// PAID-path `amount_max_cumulative` KAT (§7.3.8). This is the one
        /// counter-bearing caveat that can ONLY be exhausted on the paid branch:
        /// its consume charges `action_cost` (the free path's `action_cost == 0`
        /// never advances the cumulative sum against a positive cap). Drives
        /// `reserve_outlet_economy` on the paid branch (`per_outlet_call` = 5)
        /// with a cumulative cap of 12: two calls admit (5, then 10), the third
        /// (would-be 15 > 12) rejects naming `amountMaxCumulative`. Proves the
        /// `consume_caveat_counters` `AmountCumulative` arm (`outlets_helpers.rs`
        /// ~1557) is live on the paid path and that the running total — not a
        /// per-call amount — is what trips the cap.
        #[tokio::test]
        async fn reserve_paid_path_enforces_amount_max_cumulative() {
            let deps = build_deps_paid(Box::new(OkPersistence)).await;
            let mut cell = ClassSCell::new(paid_active_state());
            let mut caveats = InvocationCaveats::empty();
            // Cap = 12; each paid call charges the per_outlet_call cost (5), so the
            // cumulative sum is 5 -> 10 -> (would-be 15, rejected).
            caveats.amount_max_cumulative = Some(Amount::new(12));
            let cid = "cid-paid-amt";
            let input = serde_json::json!({});
            let now = scp_clock::SystemClock.now_secs();

            let spending1 = signed_spending_ucan_for(&DID(INVOKER.to_owned()));
            paid_reserve_step(&mut cell, &deps, &spending1, &caveats, cid, &input, now)
                .await
                .expect("first paid reserve: cumulative 5 <= 12 admits");
            assert_eq!(
                cell.class_s.caveat_counters[cid].amount_cumulative_used, 5,
                "the paid path charged the per_outlet_call cost against the cumulative counter"
            );

            let spending2 = signed_spending_ucan_for(&DID(INVOKER.to_owned()));
            paid_reserve_step(&mut cell, &deps, &spending2, &caveats, cid, &input, now)
                .await
                .expect("second paid reserve: cumulative 10 <= 12 admits");
            assert_eq!(cell.class_s.caveat_counters[cid].amount_cumulative_used, 10);

            let spending3 = signed_spending_ucan_for(&DID(INVOKER.to_owned()));
            let err = paid_reserve_step(&mut cell, &deps, &spending3, &caveats, cid, &input, now)
                .await
                .expect_err("third paid reserve: cumulative would be 15 > 12");
            assert!(
                format!("{err}").contains("amountMaxCumulative"),
                "the reject must name the amountMaxCumulative caveat: {err}"
            );
            // The rejected call did not advance the cumulative counter past its
            // last admitted value (all-or-nothing consume on a clone).
            assert_eq!(
                cell.class_s.caveat_counters[cid].amount_cumulative_used, 10,
                "a rejected paid reserve leaves the cumulative counter at its last admitted total"
            );
        }
    }

    /// Sub-chunk 3a — streaming open-time economy reserve
    /// ([`reserve_outlet_stream_economy`]).
    ///
    /// Covers the escrow-debit math (`cost × count`, `cost == 0 → 0`, checked
    /// overflow), the generation/economic-policy capture, the not-a-member
    /// reject, and the budget reversal on persist failure. No per-sender
    /// sequence is allocated at reserve (allocate-at-consumption), so the tests
    /// assert the membership sequence counter is left UNTOUCHED.
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    mod stream_reserve {
        use std::sync::Arc;

        use scp_did::DID;
        use scp_protocol::economy::types::{Amount, EconomicPolicy};

        use crate::context::ContextError;
        use crate::context::ContextState;
        use crate::context::actor::class_s::ClassSCell;
        use crate::context::actor::deps::ActorDeps;
        use crate::context::actor::state::PerContextState;

        const INVOKER: &str = "did:dht:z6MkStreamInvoker";
        const CTX_BYTE: u8 = 0x57;
        const NOW: u64 = 1_700_000_000;

        fn ctx_key() -> String {
            hex::encode([CTX_BYTE; 32])
        }

        fn invoker() -> DID {
            DID(INVOKER.to_owned())
        }

        /// Persistence double whose `persist_context` always SUCCEEDS.
        struct OkPersistence;
        #[async_trait::async_trait]
        impl crate::context::persistence::ContextPersistence for OkPersistence {
            async fn persist_context(
                &self,
                _: &str,
                _: &crate::context::state::ContextSnapshot,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

        /// Persistence double whose `persist_context` always FAILS — drives the
        /// fail-closed escrow-debit compensation path.
        struct FailPersistence;
        #[async_trait::async_trait]
        impl crate::context::persistence::ContextPersistence for FailPersistence {
            async fn persist_context(
                &self,
                _: &str,
                _: &crate::context::state::ContextSnapshot,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Err("induced persist failure".into())
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

        async fn build_deps(
            persistence: Box<dyn crate::context::persistence::ContextPersistence>,
        ) -> ActorDeps {
            use crate::context::supervisor::supervisor::Supervisor;
            use scp_platform::in_memory::InMemoryStorage;

            let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
                INVOKER.to_owned(),
                Arc::new(scp_clock::SystemClock),
            ));
            let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
                Box::new(crate::context::builder::NotConfiguredTransportProvider);
            let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
                Box::new(crate::context::providers::MerkleEventLogProvider::new());
            let key_resolver: scp_protocol::context::governance::KeyResolver =
                Arc::new(|_, _| None);
            let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
                Arc::new(
                    crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
                        Arc::new(InMemoryStorage::new()),
                    ),
                );
            let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::TestClock::new(NOW));
            let supervisor = Supervisor::with_providers(
                crypto,
                transport,
                event_log,
                key_resolver,
                Some(persistence),
                None,
                None,
                Some(clock),
                mls_storage,
            );
            supervisor
                .build_actor_deps(&invoker())
                .await
                .expect("build_actor_deps")
        }

        /// Active context with `INVOKER` a member holding `budget` spendable.
        fn member_state(budget: u64) -> PerContextState {
            let mut state = PerContextState::new_for_test_encrypted([CTX_BYTE; 32], NOW, invoker());
            state
                .handle
                .transition_to(&ContextState::Active)
                .expect("transition to Active");
            state
                .membership
                .add_member(invoker(), "member".to_owned(), Vec::new());
            if budget > 0 {
                state
                    .governance
                    .budget_tracker
                    .grant(&invoker(), Amount::new(budget));
            }
            state
        }

        fn economic_policy() -> EconomicPolicy {
            use scp_protocol::economy::types::{CostSchedule, CurrencyCode};
            EconomicPolicy {
                locked: false,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: None,
                    per_outlet_call: Some(Amount::new(10)),
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec![],
                pricing_formula: None,
                payee: DID::from("did:key:stream-payee"),
            }
        }

        async fn reserve(
            cell: &mut ClassSCell,
            deps: &ActorDeps,
            cost: u64,
            count: u32,
            max_per_action: Option<u64>,
        ) -> Result<super::super::StreamEconomyReservation, ContextError> {
            super::super::reserve_outlet_stream_economy(
                cell,
                deps,
                &ctx_key(),
                &invoker(),
                Amount::new(cost),
                count,
                max_per_action.map(Amount::new),
                NOW,
            )
            .await
        }

        /// Success: `reserved = cost × count` is DEBITED, and the reservation
        /// captures the generation and economic-policy snapshot. No per-sender
        /// sequence is allocated (allocate-at-consumption).
        #[tokio::test]
        async fn debits_escrow_and_captures_fields() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut state = member_state(1000);
            state.governance.economic_policy = Some(economic_policy());
            let mut cell = ClassSCell::new(state);
            let generation = cell.generation;

            let reservation = reserve(&mut cell, &deps, 10, 4, None)
                .await
                .expect("reserve admits within budget");

            assert_eq!(
                reservation.reserved_escrow,
                Amount::new(40),
                "reserved_escrow = cost 10 × count 4"
            );
            assert_eq!(
                reservation.generation, generation,
                "the reservation captures the actor generation"
            );
            assert_eq!(
                reservation.economic_policy,
                Some(economic_policy()),
                "the reservation snapshots the economic policy at acceptance"
            );
            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(40),
                "the 40-unit escrow hold is DEBITED against the invoker's budget"
            );
            assert_eq!(
                cell.membership.get(INVOKER).unwrap().sequence_number,
                0,
                "the reserve does NOT allocate a per-sender sequence \
                 (allocate-at-consumption) — the counter is left at 0"
            );
        }

        /// Successive opens each debit their own hold and NEVER touch the
        /// per-sender sequence counter (allocate-at-consumption).
        #[tokio::test]
        async fn escrow_debits_across_opens_without_touching_sequence() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut cell = ClassSCell::new(member_state(1000));

            let _first = reserve(&mut cell, &deps, 10, 2, None)
                .await
                .expect("first open");
            let _second = reserve(&mut cell, &deps, 10, 3, None)
                .await
                .expect("second open");

            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(50),
                "both holds (20 + 30) are debited"
            );
            assert_eq!(
                cell.membership.get(INVOKER).unwrap().sequence_number,
                0,
                "neither open advanced the per-sender sequence counter"
            );
        }

        /// `cost_per_chunk == 0` (Query / zero-cost) short-circuits to a zero
        /// hold with no debit and no balance consultation — and, like every
        /// open, allocates no per-sender sequence.
        #[tokio::test]
        async fn zero_cost_reserves_nothing() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            // No budget at all — a zero-cost open must not consult the balance.
            let mut cell = ClassSCell::new(member_state(0));

            let reservation = reserve(&mut cell, &deps, 0, 5, None)
                .await
                .expect("zero-cost open admits without budget");

            assert_eq!(
                reservation.reserved_escrow,
                Amount::new(0),
                "zero cost → zero hold"
            );
            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(0),
                "no debit for a zero-cost stream"
            );
            assert_eq!(
                cell.membership.get(INVOKER).unwrap().sequence_number,
                0,
                "a zero-cost open allocates no per-sender sequence either"
            );
        }

        /// `cost × count` overflow → an escrow-overflow error, with no budget
        /// debited and the per-sender sequence counter left untouched.
        #[tokio::test]
        async fn overflow_rejects_and_rolls_back() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut cell = ClassSCell::new(member_state(1000));

            let err = reserve(&mut cell, &deps, u64::MAX, 2, None)
                .await
                .expect_err("cost u64::MAX × count 2 overflows");

            assert!(
                format!("{err}").contains("economic.escrow-overflow"),
                "the overflow reject names the escrow-overflow slug: {err}"
            );
            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(0),
                "overflow rejects BEFORE any debit"
            );
            assert_eq!(
                cell.membership.get(INVOKER).unwrap().sequence_number,
                0,
                "the per-sender sequence counter is never allocated at reserve"
            );
        }

        /// `reserved > effective_remaining` → an insufficient-funds error, with
        /// no budget debited and the per-sender sequence counter left untouched.
        #[tokio::test]
        async fn insufficient_funds_rejects_and_rolls_back() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            // Budget 50, but the reservation wants 10 × 100 = 1000.
            let mut cell = ClassSCell::new(member_state(50));

            let err = reserve(&mut cell, &deps, 10, 100, None)
                .await
                .expect_err("reserved 1000 > remaining 50");

            assert!(
                format!("{err}").contains("economic.insufficient-funds"),
                "the reject names the insufficient-funds slug: {err}"
            );
            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(0),
                "insufficient funds rejects BEFORE any debit"
            );
            assert_eq!(
                cell.membership.get(INVOKER).unwrap().sequence_number,
                0,
                "the per-sender sequence counter is never allocated at reserve"
            );
        }

        /// The §19.5 `max_per_action` ceiling AND-folds into the effective
        /// spendable balance: a reservation under the raw balance but over the
        /// per-action cap is rejected.
        #[tokio::test]
        async fn max_per_action_ceiling_gates_reservation() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            // Balance 1000, but the per-action cap is 30 while the reservation
            // wants 10 × 5 = 50.
            let mut cell = ClassSCell::new(member_state(1000));

            let err = reserve(&mut cell, &deps, 10, 5, Some(30))
                .await
                .expect_err("reserved 50 > per-action cap 30");

            assert!(
                format!("{err}").contains("economic.insufficient-funds"),
                "the per-action ceiling reject reuses the insufficient-funds slug: {err}"
            );
            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(0),
                "the capped reservation debits nothing"
            );
        }

        /// A non-member has no per-sender sequence counter → reject.
        #[tokio::test]
        async fn rejects_non_member() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut state = PerContextState::new_for_test_encrypted([CTX_BYTE; 32], NOW, invoker());
            state
                .handle
                .transition_to(&ContextState::Active)
                .expect("transition to Active");
            state
                .governance
                .budget_tracker
                .grant(&invoker(), Amount::new(1000));
            // NOTE: no `add_member` — the invoker is not on the roster.
            let mut cell = ClassSCell::new(state);

            let err = reserve(&mut cell, &deps, 10, 4, None)
                .await
                .expect_err("a non-member cannot open a stream");

            assert!(
                matches!(err, ContextError::PermissionDenied(_)),
                "a non-member open is a permission denial: {err:?}"
            );
            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(0),
                "a rejected non-member open debits nothing"
            );
        }

        /// A fail-closed escrow-debit persist failure reverses the budget debit
        /// (the compensation path); the per-sender sequence counter is never
        /// allocated at reserve, so it stays untouched throughout.
        #[tokio::test]
        async fn persist_failure_reverses_budget_and_sequence() {
            let deps = build_deps(Box::new(FailPersistence)).await;
            let mut cell = ClassSCell::new(member_state(1000));

            let err = reserve(&mut cell, &deps, 10, 4, None)
                .await
                .expect_err("a failed escrow-debit persist rejects the open");

            assert!(
                matches!(err, ContextError::PersistenceFailed(_)),
                "a failed fail-closed persist surfaces PersistenceFailed: {err:?}"
            );
            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(0),
                "the budget debit is REVERSED when the persist does not land"
            );
            assert_eq!(
                cell.membership.get(INVOKER).unwrap().sequence_number,
                0,
                "the per-sender sequence counter is never allocated at reserve"
            );
        }

        // -------------------------------------------------------------------
        // reserve_stream_grant_escrow — §5.4.5 mid-stream GRANT top-up
        // -------------------------------------------------------------------

        /// A fixed stream `request_id` keying the crash-recovery record the
        /// grant reserve bumps.
        const GRANT_REQ: scp_protocol::context::outlets::stream::RequestId = [7u8; 16];

        /// Seeds a durable open-time crash-recovery record for `GRANT_REQ` with
        /// `open_hold` escrow — mirrors what the open path persists once a stream
        /// has debited an escrow hold. Lets the grant tests assert the record's
        /// `reserved_escrow` tracks `open + Σgrants`.
        fn seed_open_record(state: &mut PerContextState, open_hold: u64) {
            state.class_s.stream_reservations.insert(
                hex::encode(GRANT_REQ),
                crate::context::outlets::invoke::StreamReservationRecord {
                    invoker_did: invoker(),
                    ucan_cid: String::new(),
                    cost_per_chunk: Amount::new(10),
                    amount_cumulative_reserved: 0,
                    reserved_escrow: Amount::new(open_hold),
                    generation: 0,
                },
            );
        }

        async fn grant_reserve(
            cell: &mut ClassSCell,
            deps: &ActorDeps,
            cost: u64,
            grant: u32,
        ) -> Result<Amount, ContextError> {
            super::super::reserve_stream_grant_escrow(
                cell,
                deps,
                &ctx_key(),
                &invoker(),
                GRANT_REQ,
                Amount::new(cost),
                grant,
            )
            .await
        }

        /// Success: a grant DEBITS `cost_per_chunk × grant` from the invoker's
        /// budget, returns exactly that hold (the amount the bridge threads into
        /// `apply_credit_grant` as `reserved_top_up`), AND bumps the durable
        /// crash-recovery record's `reserved_escrow` by the same amount so a
        /// hard crash refunds `open + grant`.
        #[tokio::test]
        async fn grant_debits_incremental_escrow_and_bumps_record() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut state = member_state(1000);
            seed_open_record(&mut state, 50); // open-time hold
            let mut cell = ClassSCell::new(state);

            let reserved = grant_reserve(&mut cell, &deps, 10, 4)
                .await
                .expect("grant reserve admits within budget");

            assert_eq!(reserved, Amount::new(40), "reserved = cost 10 × grant 4");
            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(40),
                "the 40-unit grant hold is DEBITED against the invoker's budget"
            );
            assert_eq!(
                cell.class_s.stream_reservations[&hex::encode(GRANT_REQ)].reserved_escrow,
                Amount::new(90),
                "the crash-recovery record tracks open 50 + grant 40 = 90"
            );
        }

        /// A grant on a stream that reserved ZERO escrow at open (no record was
        /// persisted) CREATES an escrow-only record so the top-up is still
        /// crash-covered.
        #[tokio::test]
        async fn grant_creates_record_when_open_reserved_nothing() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut cell = ClassSCell::new(member_state(1000)); // no seeded record

            let _ = grant_reserve(&mut cell, &deps, 10, 3)
                .await
                .expect("grant reserve");

            assert_eq!(
                cell.class_s.stream_reservations[&hex::encode(GRANT_REQ)].reserved_escrow,
                Amount::new(30),
                "the first grant creates the record with reserved_escrow = grant 30"
            );
        }

        /// A grant does NOT run the hard-rate / velocity / membership gates the
        /// OPEN reserve does — successive grants each debit their own hold and
        /// accumulate (bounding real spend behind every credit extension).
        #[tokio::test]
        async fn successive_grants_accumulate_debits() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut cell = ClassSCell::new(member_state(1000));

            let _a = grant_reserve(&mut cell, &deps, 10, 2)
                .await
                .expect("grant a");
            let _b = grant_reserve(&mut cell, &deps, 10, 3)
                .await
                .expect("grant b");

            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(50),
                "both grant holds (20 + 30) are debited"
            );
        }

        /// Zero-cost / Query outlets perform NO grant top-up (spec §5.4.5).
        #[tokio::test]
        async fn zero_cost_grant_reserves_nothing() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut cell = ClassSCell::new(member_state(0));

            let reserved = grant_reserve(&mut cell, &deps, 0, 5)
                .await
                .expect("zero-cost grant admits without budget");

            assert_eq!(reserved, Amount::new(0), "zero cost → zero hold");
            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(0),
                "no debit for a zero-cost grant"
            );
        }

        /// A zero-chunk grant is a no-op debit (defensive; the bridge never
        /// signs a `grant == 0`).
        #[tokio::test]
        async fn zero_grant_reserves_nothing() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut cell = ClassSCell::new(member_state(1000));

            let reserved = grant_reserve(&mut cell, &deps, 10, 0)
                .await
                .expect("zero-chunk grant admits");

            assert_eq!(reserved, Amount::new(0), "grant 0 → zero hold");
            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(0),
                "no debit for a zero-chunk grant"
            );
        }

        /// `cost × grant` overflow → an escrow-overflow error with no debit.
        #[tokio::test]
        async fn grant_overflow_rejects_before_debit() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut cell = ClassSCell::new(member_state(1000));

            let err = grant_reserve(&mut cell, &deps, u64::MAX, 2)
                .await
                .expect_err("cost u64::MAX × grant 2 overflows");

            assert!(
                format!("{err}").contains("economic.escrow-overflow"),
                "the overflow reject names the escrow-overflow slug: {err}"
            );
            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(0),
                "overflow rejects BEFORE any debit"
            );
        }

        /// `cost × grant > remaining` → insufficient-funds with no debit — the
        /// budget cap keeps bounding real spend across grants.
        #[tokio::test]
        async fn grant_insufficient_funds_rejects_before_debit() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut cell = ClassSCell::new(member_state(50));

            let err = grant_reserve(&mut cell, &deps, 10, 100)
                .await
                .expect_err("grant 10 × 100 = 1000 > remaining 50");

            assert!(
                format!("{err}").contains("economic.insufficient-funds"),
                "the reject names the insufficient-funds slug: {err}"
            );
            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(0),
                "insufficient funds rejects BEFORE any debit"
            );
        }

        /// A grant hold that a rejected apply must reverse round-trips to a net
        /// ZERO debit AND leaves the durable record un-bumped: reserve DEBITS +
        /// bumps the record, then `reverse_stream_grant_escrow` CREDITS the
        /// budget back AND un-bumps the record ATOMICALLY — the money-
        /// conservation invariant the bridge upholds on an apply rejection. If
        /// the reverse un-bumped only the budget, a crash after it would make
        /// reconcile double-refund the still-bumped record.
        #[tokio::test]
        async fn grant_reserve_then_reverse_conserves_budget_and_record() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut state = member_state(1000);
            seed_open_record(&mut state, 50);
            let mut cell = ClassSCell::new(state);

            let reserved = grant_reserve(&mut cell, &deps, 10, 4)
                .await
                .expect("grant reserve");
            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(40),
                "the grant hold is debited"
            );
            assert_eq!(
                cell.class_s.stream_reservations[&hex::encode(GRANT_REQ)].reserved_escrow,
                Amount::new(90),
                "the record is bumped to open 50 + grant 40"
            );

            super::super::reverse_stream_grant_escrow(
                &mut cell,
                &deps,
                &ctx_key(),
                &invoker(),
                GRANT_REQ,
                reserved,
            )
            .await
            .expect("reverse the grant hold");

            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(0),
                "reverse credits the full hold back — net-zero debit (billed + refund == reserved)"
            );
            assert_eq!(
                cell.class_s.stream_reservations[&hex::encode(GRANT_REQ)].reserved_escrow,
                Amount::new(50),
                "reverse un-bumps the record back to the open-time hold (no double-refund on crash)"
            );
        }

        /// HARD-CRASH crash-recovery (HIGH — crypto): open (record persisted with
        /// the open hold) → grant (budget + record both bumped) → simulate a hard
        /// crash BEFORE any settle (the ephemeral pump escrow ledger is lost) →
        /// the restore-time `reconcile_stream_reservations` sweep refunds
        /// `open + grant`, so the invoker is NOT over-charged the grant top-up.
        #[tokio::test]
        async fn grant_then_hard_crash_reconcile_refunds_open_plus_grant() {
            let deps = build_deps(Box::new(OkPersistence)).await;
            let mut state = member_state(1000);
            seed_open_record(&mut state, 50); // open-time escrow hold, durable
            // The open hold was already debited at open; model that on the state
            // before wrapping it in the cell.
            state
                .governance
                .budget_tracker
                .record_spend(&invoker(), Amount::new(50))
                .expect("open-time debit");
            let mut cell = ClassSCell::new(state);

            // A grant tops up escrow by 10 × 4 = 40 (budget + durable record).
            grant_reserve(&mut cell, &deps, 10, 4)
                .await
                .expect("grant reserve");
            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(90),
                "open 50 + grant 40 debited"
            );

            // HARD CRASH before settle: the pump + its ephemeral escrow ledger
            // vanish; only the durable record survives. Restore-time reconcile
            // refunds the FULL record (billed unknown post-crash — service-
            // rendered billing is captured elsewhere, so full refund is the
            // conservative, no-over-charge choice).
            let refunded =
                super::super::reconcile_stream_reservations(&mut cell, &deps, &ctx_key())
                    .await
                    .expect("reconcile sweep");
            assert_eq!(refunded, 1, "one unresolved record reconciled");

            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(0),
                "reconcile refunds open 50 + grant 40 = 90 — the invoker is NOT over-charged \
                 the grant top-up (the pre-fix bug refunded only the open 50)"
            );
            assert!(
                cell.class_s.stream_reservations.is_empty(),
                "the reconciled record is cleared"
            );
        }

        /// A fail-closed persist failure during the grant debit reverses the
        /// debit AND restores the record bump (the `commit_class_s_compensating`
        /// snapshot-restore path) — no funds stranded, record unchanged.
        #[tokio::test]
        async fn grant_persist_failure_reverses_debit_and_restores_record() {
            let deps = build_deps(Box::new(FailPersistence)).await;
            let mut state = member_state(1000);
            seed_open_record(&mut state, 50);
            let mut cell = ClassSCell::new(state);

            let err = grant_reserve(&mut cell, &deps, 10, 4)
                .await
                .expect_err("a failed grant-debit persist rejects the top-up");

            assert!(
                matches!(err, ContextError::PersistenceFailed(_)),
                "a failed fail-closed persist surfaces PersistenceFailed: {err:?}"
            );
            assert_eq!(
                cell.class_s.stream_reservations[&hex::encode(GRANT_REQ)].reserved_escrow,
                Amount::new(50),
                "the record bump is RESTORED on persist failure (back to the open hold)"
            );
            assert_eq!(
                cell.governance.budget_tracker.total_spent(&invoker()),
                Amount::new(0),
                "the grant debit is REVERSED when the persist does not land"
            );
        }
    }
}
