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
use scp_protocol::economy::types::Amount;

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
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn reserve_outlet_economy(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    invoker_did: &DID,
    spending_ucan: Option<&UcanToken>,
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

fn invocation_error_to_context(err: InvocationError) -> ContextError {
    match err {
        InvocationError::ContextNotActive { current_state } => ContextError::PermissionDenied(
            format!("SCP-OUTLET-6080: context not active: {current_state}"),
        ),
        InvocationError::InvokerNotAuthorized { did, outlet_id } => ContextError::PermissionDenied(
            format!("SCP-OUTLET-6081: invoker {did} lacks OutletCall({outlet_id})"),
        ),
        InvocationError::OutletNotFound { outlet_id } => {
            ContextError::PermissionDenied(format!("SCP-OUTLET-6082: outlet not found: {outlet_id}"))
        }
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
        InvocationError::Cancelled => {
            ContextError::PermissionDenied("SCP-OUTLET-6087: outlet invocation cancelled".to_owned())
        }
        InvocationError::BudgetExceeded {
            did,
            cost,
            remaining,
        } => ContextError::PermissionDenied(format!(
            "SCP-ECON-12010: budget exceeded for {did}: cost {cost}, remaining {remaining}"
        )),
    }
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
            use scp_platform::testing::InMemoryStorage;

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
}
