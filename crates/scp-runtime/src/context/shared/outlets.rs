//! Items the outlets domain shares with core and with other domains.
//!
//! It holds code that reads or writes only core state and calls no domain
//! function, and the types and constants more than one crate names (ADR-070
//! Appendix).
use crate::context::ContextHandle;
use crate::context::actor::deps::ActorDeps;
use crate::context::outlets::invoke;
use crate::context::outlets::invoke::InvocationError;
use crate::context::outlets::invoke::InvokeExecuteOutcome;
use crate::context::outlets::invoke::build_outlet_event;
use crate::context::outlets::invoke::invoke_outlet_execute_and_validate;
use crate::economy::adapter::PaymentReceipt;
use crate::economy::integration::PreparedAction;
use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::lifecycle::OutletInvokedEvent;
use scp_protocol::context::outlets::registry::OutletRegistry;
use scp_protocol::context::roles::ContextRoleState;
use scp_protocol::economy::antispam::VelocityRollbackToken;
use scp_protocol::economy::policy::ObservableMetrics;
use scp_protocol::economy::types::Amount;
use scp_protocol::trust::caveats::InvocationCaveats;
use std::future::Future;
use std::sync::Arc;

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

/// Phase-1 bookkeeping bundle for a outlet invocation in flight.
///
/// Crosses the actor mailbox inside a [`OutletEconomyReservation`]: produced by
/// [`reserve_outlet_economy`] (actor), carried through the executor
/// (supervisor), then consumed by [`settle_outlet_economy_capture`] /
/// [`rollback_outlet_economy`] (actor).
///
/// The `#[must_use]` + `Drop` debug-assert invariant catches any future
/// refactor that leaks an unbalanced budget deduction or velocity entry.
/// All fields are `Send` so the ticket can cross the mailbox boundary.
#[must_use = "OutletEconomyTicket must be committed or rolled back — dropping leaks budget, velocity, and escrow state"]
pub struct OutletEconomyTicket {
    /// The invoking member the bookkeeping is charged to.
    pub actor_did: DID,
    /// The budget deduction a rollback reverses, if one was made.
    pub deducted_cost: Option<Amount>,
    /// The token that undoes the velocity entry.
    pub velocity_token: VelocityRollbackToken,
    /// The external escrow hold, captured on settle or voided on rollback.
    pub escrow: Option<PreparedAction>,
    /// The economic policy the capture prices against.
    pub policy_for_capture: Option<scp_protocol::economy::types::EconomicPolicy>,
    /// The metrics the capture prices from.
    pub metrics_for_capture: ObservableMetrics,
    /// Whether a rollback refunds the hard rate-limit slot.
    pub needs_hard_rate_limit_refund: bool,
    /// Set once the ticket is settled or rolled back, so `Drop` does not fire.
    pub consumed: bool,
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
    /// [`CallerReservationRecord`](crate::context::supervisor::saga_prepared_state::CallerReservationRecord) (spec §6.2.4) so a cross-context saga's
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
    #[must_use]
    pub fn to_caller_reservation_record(
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

/// The `Send` output of the Phase-1 economy reserve.
///
/// Produced by [`reserve_outlet_economy`] inside the actor, carried by the
/// supervisor orchestrator across the non-`Send` executor, and handed back into
/// the actor for Phase 3 settle.
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

/// The `Send` output of the streaming open reserve
/// ([`reserve_outlet_stream_economy`]).
///
/// Mirrors [`OutletEconomyReservation`] for the streaming-native invocation
/// path: produced inside the per-context actor on owned Class-S state, carried
/// by the supervisor orchestrator across the non-`Send` off-mailbox pump, and
/// consumed by the close-time settlement (a later sub-chunk).
///
/// Unlike the unary reservation this carries NO in-flight
/// [`OutletEconomyTicket`]: the streaming path holds its economic reservation
/// as a debited `reserved_escrow` against the invoker's budget (refunded, net
/// of billed chunks, at stream close). The `economic_policy` is snapshotted at
/// acceptance so close-time settlement can capture the §19.15.5
/// `PaymentReceipt` for rendered service even if the context is torn down
/// mid-stream.
///
/// This reservation carries no send-sequence; A's re-seal draws A's own
/// persistent per-sender counter at the §9.16/§5.15.7 encrypt seam (SCP-OUT-047)
/// — do not mint a bridge-local counter here.
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

/// The `SCP-OUTLET-6089` "invoker is not a member" marker string.
///
/// Stamped into the `PermissionDenied` message by the
/// [`reserve_outlet_stream_economy`] membership gate and matched back out by
/// [`reserve_error_to_open_rejection`]. Kept as one const so the producer and
/// the reverse-map consumer move together — a permanent membership/authorization
/// denial must map to a NON-retryable class, never the retryable transport
/// rate-limit the catch-all uses (mirrors the 6080 marker discipline).
pub const SCP_OUTLET_6089_MARKER: &str = "SCP-OUTLET-6089";

/// Authorizes and captures the exact `billed_amount` for a closed §5.4.5 stream.
///
/// It is the actor-mailbox port of the `authorize_dyn → capture_dyn` sequence
/// in the reference `ContextManager::outlet_stream_settle`.
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

/// Phase 3 of the outlet economy pipeline on executor FAILURE, run inside
/// the per-context actor on owned state.
///
/// Voids any payment escrow hold, then reverses the velocity entry, budget
/// deduction, and hard-rate-limit token consumed by [`reserve_outlet_economy`].
/// Generation-checked Phase-3 rollback. Reverses the reservation against THIS
/// actor's owned state ONLY if the reservation's `generation` still matches the
/// live actor's `state.generation`; on a MISMATCH the actor was despawned and a
/// new instance respawned for the same `context_id` between reserve and this
/// rollback (e.g. an import replace), so refunding velocity / budget /
/// hard-rate-limit against THIS instance's owned state would be a
/// confused-deputy write to the WRONG context instance. On mismatch it voids
/// only the EXTERNAL escrow (the real payment hold the prior instance
/// authorized at reserve) and consumes the ticket — exactly mirroring
/// [`settle_outlet_economy`]'s generation guard, but for the failure/abort
/// path.
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

/// Rolls back an outlet invocation's reservation: voids the external escrow,
/// then reverses the velocity entry, the hard rate-limit slot and the budget
/// deduction, and consumes the ticket.
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

/// The Phase-3 settle request of an outlet invocation.
///
/// [`invoke_outlet_with_economy`] hands it to the supervisor-supplied `settle`
/// closure, which carries it into the actor via
/// [`OutletsCommand::SettleOutletEconomy`](crate::context::actor::commands::OutletsCommand::SettleOutletEconomy).
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

/// Projects an [`InvocationError`] onto the typed `ContextError::Outlet`.
///
/// The [`ContextError::Outlet`](scp_protocol::context::ContextError::Outlet)
/// carries the full §5.4.4
/// [`OutletErrorSurface`](scp_protocol::context::outlets::errors::OutletErrorSurface)
/// (SCP-OUT-031 PR-2a).
///
/// This is the **root-cause fix** for SCP-OUT-031 PR-2a. Outlet invocation
/// errors previously flattened here to `ContextError::PermissionDenied(String)`
/// — collapsing every `class` / `detail` / `retry` / `source_chain`
/// distinction into a prose `SCP-OUTLET-NNNN:` string BEFORE the FFI boundary,
/// so the three `From<OutletError>` bridge impls (and every SDK) could only
/// re-parse a code prefix out of the message. The structured surface now
/// crosses the runtime → `ContextError` seam intact; the bridges (PR-2b) and
/// SDKs rebuild the typed error hierarchy losslessly.
///
/// The per-variant `(class, code, slug, detail, retry)` mapping is
/// single-sourced on [`InvocationError::to_surface`] — never re-derived in the
/// bridges.
pub fn invocation_error_to_context(
    err: impl Into<crate::context::outlets::invoke::OutletOpenError>,
) -> ContextError {
    use crate::context::outlets::invoke::OutletOpenError;
    match err.into() {
        OutletOpenError::SupervisorShutDown { message } => {
            ContextError::SupervisorShutDown(message)
        }
        OutletOpenError::Invocation(other) => ContextError::Outlet(Box::new(other.to_surface())),
    }
}

/// Maps the streaming reserve's [`ContextError`] to an open-time rejection.
///
/// The target is the
/// [`OpenStreamRejection`](crate::context::outlets::dispatch::OpenStreamRejection)
/// taxonomy of the
/// [`Supervisor::open_outlet_stream`](crate::context::supervisor::supervisor::Supervisor::open_outlet_stream)
/// orchestrator.
///
/// A [`ContextError::SupervisorShutDown`] maps to
/// [`OutletStreamOpenError::SupervisorShutDown`](crate::context::outlets::invoke::OutletStreamOpenError::SupervisorShutDown)
/// instead.
///
/// # Mapping direction (documented per the chunk-3 plan §3a note)
///
/// The streaming reserve ([`reserve_outlet_stream_economy`]) runs INSIDE the
/// per-context actor and can only reply with a `Send` [`ContextError`] across
/// the mailbox, so it encodes its two economic open-time rejections through the
/// LOSSLESS forward direction —
/// [`OpenStreamRejection::to_open_error`](crate::context::outlets::dispatch::OpenStreamRejection::to_open_error)
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
#[must_use]
pub fn reserve_error_to_open_rejection(
    err: &ContextError,
) -> crate::context::outlets::invoke::OutletStreamOpenError {
    use crate::context::outlets::dispatch::OpenStreamRejection;
    use crate::context::outlets::invoke::OutletStreamOpenError;
    use scp_protocol::context::outlets::error_codes;

    let rejection = match err {
        ContextError::RateLimited { .. } => OpenStreamRejection::AdmissionRateLimited {
            slug: error_codes::SLUG_TRANSPORT_RATE_LIMITED,
        },
        // SCP-OUT-031 PR-2a: outlet errors now cross the actor mailbox as the
        // typed `ContextError::Outlet(surface)` (the pre-PR-2a
        // `PermissionDenied(String)` flattening is gone). Route by the surface's
        // structured `slug` / `code` — the SAME `error_codes::SLUG_*` / `CODE_*`
        // constants the reserve stamped — instead of `msg.contains(...)` on a
        // prose string, so the two ends still move together if a slug/code is
        // renamed.
        ContextError::Outlet(surface)
            if surface.slug == error_codes::SLUG_ECONOMIC_ESCROW_OVERFLOW =>
        {
            OpenStreamRejection::EscrowOverflow
        }
        ContextError::Outlet(surface)
            if surface.slug == error_codes::SLUG_ECONOMIC_INSUFFICIENT_FUNDS =>
        {
            OpenStreamRejection::InsufficientFunds
        }
        // #2196 error-masking fix — the `ensure_context_active` gate returns the
        // typed `ContextError::OutletContextNotActive { current_state }` carrier
        // (SCP-OUT-031 PR-2a). Read `current_state` TYPED into the stream-open
        // surface's `ContextNotActive` rejection (`protocol.context-closed-mid-
        // stream` / `SCP-OUTLET-6101`, the NON-retryable Protocol class) rather
        // than letting it fall through to the catch-all below, which collapses
        // everything into the RETRYABLE transport rate-limit slug — a permanent
        // "context not active" failure must never be reported as a transient,
        // retryable condition. `current_state` stays internal: it rides the
        // typed carrier here and the stream-open FFI seam (`open_rejection_to_err`)
        // emits only the code + slug, never the state.
        ContextError::OutletContextNotActive { current_state } => {
            OpenStreamRejection::ContextNotActive {
                current_state: current_state.to_string(),
            }
        }
        // #2196 error-masking fix — the membership gate emits SCP-OUTLET-6089
        // (invoker is not a member of the context) as a plain `PermissionDenied`.
        // `open_outlet_stream_phase1` runs no membership check before the reserve,
        // so a non-member same-context open flows here. It is a PERMANENT
        // authorization denial — map it to the non-retryable authorization-denied
        // class (`authorization.denied` → CODE_AUTHORIZATION_DENIED,
        // SCP-OUTLET-6110, RetryPolicy::Never), NOT the retryable transport
        // rate-limit the catch-all uses. Routed through `CaveatPostInputViolation`
        // (its non-schema slug branch yields CODE_AUTHORIZATION_DENIED), matching
        // how `invocation_error_to_open_rejection` maps `InvokerNotAuthorized`.
        ContextError::PermissionDenied(msg) if msg.contains(SCP_OUTLET_6089_MARKER) => {
            OpenStreamRejection::CaveatPostInputViolation {
                slug: error_codes::SLUG_AUTHORIZATION_DENIED.to_owned(),
            }
        }
        // Shutdown has begun (ADR-049 Decision 16, item 2): the open takes the
        // Supervisor's shutdown refusal, never the retryable transport slug below.
        ContextError::SupervisorShutDown(message) => {
            return OutletStreamOpenError::SupervisorShutDown {
                message: message.clone(),
            };
        }
        // A persist failure / mailbox fault / any other reserve error is GENUINELY
        // transient — keep it on the retryable transport-fault path.
        _ => OpenStreamRejection::AdmissionRateLimited {
            slug: error_codes::SLUG_TRANSPORT_RATE_LIMITED,
        },
    };
    OutletStreamOpenError::Rejected(rejection)
}

/// Builds the §7.3.8 post-input caveat hook for a streaming open.
///
/// It is built ENTIRELY inside the runtime, from the streaming open's own
/// inputs, so every bridge gets identical, complete enforcement without
/// supplying any hook.
///
/// Ported from the reference `ContextManager::build_stream_post_input_hook`
/// onto the actor architecture (the counter store is the actor-owned
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
///
/// # Errors
///
/// The `CaveatPostInputViolation` rejection above.
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

/// The pair returned by [`build_stream_post_input_hook`]: the synchronous
/// §7.3.8 local-check hook and the durable counter reservation committed at the
/// dispatch pump's final open-time gate.
pub type StreamPostInputBuild = (
    Option<crate::context::outlets::invoke::CaveatPostInputCheck<'static>>,
    Option<crate::context::outlets::dispatch::StreamCounterReservation>,
);
