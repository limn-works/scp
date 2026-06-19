//! Tools helpers -- actor-shape signatures
//! (ADR-049 Phase 2A.4 + Phase 2A finalization, `tools` domain).
//!
//! # Purpose
//!
//! This module hosts tools-domain helpers that actor handlers call with
//! actor-owned state (`&mut PerContextState`). Two surfaces live here:
//!
//! 1. The hard-rate-limit consume / refund helpers
//!    ([`try_consume_hard_rate_limit`], [`refund_hard_rate_limit`]).
//! 2. The economy-pipeline split for tool invocation
//!    ([`reserve_tool_economy`], [`settle_tool_economy_capture`],
//!    [`rollback_tool_economy`]) plus the supervisor-side orchestrator
//!    [`invoke_tool_with_economy`].
//!
//! # The `invoke_tool_with_economy` actor split (Phase 2A finalization)
//!
//! The legacy `invoke_tool_with_economy` ran the entire economy pipeline
//! under the `contexts` `DashMap` mutex (Phase 1 reserve), dropped the
//! lock, ran the executor off-lock (Phase 2), then re-locked for
//! post-invocation bookkeeping (Phase 3). ADR-049 deletes the `DashMap`,
//! so per-context state now lives ONLY inside the per-context actor.
//!
//! The tool executor is a non-`Send` generic `FnOnce` closure (FFI
//! bridges supply GIL-bound / JS-bound closures) that cannot cross the
//! actor mailbox. The economy bookkeeping, by contrast, is `Send` and
//! mutates owned [`PerContextState`]. The split therefore runs:
//!
//! - **Phase 1 (reserve)** — [`reserve_tool_economy`] runs INSIDE the
//!   actor handler ([`ToolsCommand::ReserveToolEconomy`]) on
//!   `&mut PerContextState`. It consumes the hard rate limit, records the
//!   velocity entry, runs the economy pre-check, deducts budget,
//!   authorizes the payment escrow, and returns a `Send`
//!   [`ToolEconomyReservation`] (context handle + role-state snapshot +
//!   the in-flight [`ToolEconomyTicket`]).
//! - **Phase 2 (execute)** — the supervisor-side orchestrator
//!   [`invoke_tool_with_economy`] runs the non-`Send` executor through
//!   [`invoke_tool_execute_and_validate`] BETWEEN the two mailbox
//!   round-trips. No lock is held; the actor is free to process other
//!   commands.
//! - **Phase 3 (settle)** — on executor success
//!   [`settle_tool_economy_capture`] runs inside the actor
//!   ([`ToolsCommand::SettleToolEconomy`]) to perform post-invocation
//!   bookkeeping + consequence enforcement + payment capture; on
//!   executor failure [`rollback_tool_economy`] voids the escrow and
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

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::roles::ContextRoleState;
use scp_protocol::context::tools::ToolId;
use scp_protocol::context::tools::lifecycle::ToolInvokedEvent;
use scp_protocol::context::tools::registry::ToolRegistry;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::economy::antispam::VelocityRollbackToken;
use scp_protocol::economy::policy::ObservableMetrics;
use scp_protocol::economy::types::Amount;

use crate::context::ContextHandle;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::tools::invoke::{
    self, InvocationError, InvokeExecuteOutcome, ToolEconomyContext, build_tool_event,
    economy_pre_check, invoke_tool_execute_and_validate, post_tool_invocation_bookkeeping,
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
#[allow(clippy::needless_pass_by_ref_mut)] // PerContextState is Send + !Sync; &mut keeps actor futures Send.
pub fn try_consume_hard_rate_limit(state: &mut PerContextState, did: &DID, now_secs: u64) -> bool {
    state.governance.hard_rate_limit.try_consume(did, now_secs)
}

// ---------------------------------------------------------------------------
// refund_hard_rate_limit (actor-handler entry point)
// ---------------------------------------------------------------------------

/// Refund one hard-rate-limit token for a live context actor.
///
/// Unknown-context no-op behavior remains in the supervisor shim
/// fallback; the actor path only runs after mailbox lookup succeeds.
#[allow(clippy::needless_pass_by_ref_mut)] // PerContextState is Send + !Sync; &mut keeps actor futures Send.
pub fn refund_hard_rate_limit(state: &mut PerContextState, did: &DID) {
    state.governance.hard_rate_limit.refund(did);
}

// ---------------------------------------------------------------------------
// ManagedToolInvocationOutput
// ---------------------------------------------------------------------------

/// Result of a successful managed tool invocation. Returned to the FFI
/// bridges by [`invoke_tool_with_economy`].
#[derive(Debug)]
pub struct ManagedToolInvocationOutput {
    /// Tool output JSON.
    pub output: serde_json::Value,
    /// Event to append to the event log.
    pub event: ToolInvokedEvent,
    /// Consequences triggered by the invocation.
    pub consequences: Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
    /// Payment receipt when a payment adapter is configured.
    pub payment_receipt: Option<PaymentReceipt>,
}

// ---------------------------------------------------------------------------
// ToolEconomyTicket — the in-flight economy bookkeeping bundle
// ---------------------------------------------------------------------------

/// Phase-1 bookkeeping bundle for a tool invocation in flight. Crosses
/// the actor mailbox inside a [`ToolEconomyReservation`]: produced by
/// [`reserve_tool_economy`] (actor), carried through the executor
/// (supervisor), then consumed by [`settle_tool_economy_capture`] /
/// [`rollback_tool_economy`] (actor).
///
/// The `#[must_use]` + `Drop` debug-assert invariant catches any future
/// refactor that leaks an unbalanced budget deduction or velocity entry.
/// All fields are `Send` so the ticket can cross the mailbox boundary.
#[must_use = "ToolEconomyTicket must be committed or rolled back — dropping leaks budget, velocity, and escrow state"]
pub struct ToolEconomyTicket {
    actor_did: DID,
    deducted_cost: Option<Amount>,
    velocity_token: VelocityRollbackToken,
    escrow: Option<PreparedAction>,
    policy_for_capture: Option<scp_protocol::economy::types::EconomicPolicy>,
    metrics_for_capture: ObservableMetrics,
    needs_hard_rate_limit_refund: bool,
    consumed: bool,
}

impl std::fmt::Debug for ToolEconomyTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolEconomyTicket")
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

impl Drop for ToolEconomyTicket {
    fn drop(&mut self) {
        if !self.consumed {
            tracing::error!(
                actor_did = %self.actor_did,
                cost = ?self.deducted_cost,
                "ToolEconomyTicket dropped without commit or rollback — budget, velocity, and escrow state may be inconsistent"
            );
            debug_assert!(
                false,
                "ToolEconomyTicket dropped without commit or rollback for actor {}",
                self.actor_did
            );
        }
    }
}

fn commit_tool_economy_ticket(mut ticket: ToolEconomyTicket) -> Option<Amount> {
    ticket.consumed = true;
    ticket.needs_hard_rate_limit_refund = false;
    ticket.deducted_cost
}

impl ToolEconomyTicket {
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
            invoke::void_tool_escrow(adapter.as_ref(), prepared).await;
        }
        // The context-local budget/velocity/rate-limit bookkeeping is
        // gone with the actor; mark consumed so the unbalanced-ticket
        // Drop guard does not fire.
        self.consumed = true;
        self.needs_hard_rate_limit_refund = false;
    }

    /// Synchronous last-resort consume for a sync, deps-less reply path
    /// (the [`reply_tools_not_registered`] backstop) that cannot `.await`
    /// to void the escrow. Marks the ticket consumed so its Drop balance
    /// guard does not fire, and logs at ERROR if an external escrow hold
    /// is being abandoned without a void. This path is unreachable for
    /// `SettleToolEconomy` through `dispatch_tools_command` (which voids
    /// the escrow async before reaching the sync reply); it exists only
    /// as defense-in-depth so no future caller can resurrect the
    /// ticket-drop panic.
    ///
    /// [`reply_tools_not_registered`]: crate::context::supervisor::Supervisor
    pub fn consume_abandoning_escrow(mut self) {
        if self.escrow.is_some() {
            tracing::error!(
                actor_did = %self.actor_did,
                "tool-economy ticket consumed on a sync no-actor reply path that cannot void \
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
}

// ---------------------------------------------------------------------------
// ToolEconomyReservation — the Send payload that crosses the mailbox
// ---------------------------------------------------------------------------

/// The `Send` output of the Phase-1 economy reserve. Produced by
/// [`reserve_tool_economy`] inside the actor, carried by the supervisor
/// orchestrator across the non-`Send` executor, and handed back into the
/// actor for Phase 3 settle.
///
/// Carries the context handle + role-state snapshot (the executor's
/// off-lock inputs) and the in-flight [`ToolEconomyTicket`].
#[must_use = "a ToolEconomyReservation must be settled (capture) or rolled back — dropping leaks the held ticket"]
pub struct ToolEconomyReservation {
    /// Context handle snapshot — the executor reads lifecycle state and
    /// the supervisor passes it to [`invoke_tool_execute_and_validate`].
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
    pub ticket: ToolEconomyTicket,
}

impl std::fmt::Debug for ToolEconomyReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolEconomyReservation")
            .field("ticket", &self.ticket)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Phase 1: reserve_tool_economy (actor handler entry point)
// ---------------------------------------------------------------------------

/// Phase 1 of the tool economy pipeline, run inside the per-context
/// actor on owned state. Consumes the hard rate limit, records the
/// velocity entry, runs the economy pre-check, deducts budget, validates
/// the spending UCAN, and authorizes the payment escrow.
///
/// On any failure branch the hard-rate-limit token is refunded inline
/// (and velocity rolled back / budget reversed as applicable) so a
/// rejected reservation leaves observable state unchanged. On success
/// returns a `Send` [`ToolEconomyReservation`] the supervisor carries
/// across the executor.
///
/// # Errors
///
/// Propagates [`ContextError`] for rate-limit, budget, spending-UCAN, and
/// escrow-authorization failures.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn reserve_tool_economy(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    invoker_did: &DID,
    spending_ucan: Option<&UcanToken>,
    now_secs: u64,
) -> Result<ToolEconomyReservation, ContextError> {
    let event_log = &deps.event_log;
    let key_resolver = &deps.key_resolver;
    let clock = deps.clock.as_ref();
    let payment_adapter = deps.payment_adapter.clone();

    let handle = state.handle.clone();
    let role_state = state.role_state.clone();

    // Hard rate limit — the Matrix Synapse–style defense-in-depth cap on
    // the tool path. try_consume before any Phase-1 bookkeeping.
    if !state
        .governance
        .hard_rate_limit
        .try_consume(invoker_did, now_secs)
    {
        return Err(ContextError::RateLimited {
            resource: "tool_invoke".to_owned(),
            message: "hard rate limit exceeded for invoker".to_owned(),
        });
    }

    let velocity_token = state
        .governance
        .velocity_tracker
        .record_message(invoker_did, now_secs);

    let velocity = state
        .governance
        .velocity_tracker
        .get_velocity(invoker_did, now_secs);
    let member_count = u64::try_from(state.membership.count()).unwrap_or(u64::MAX);
    let aggregate = state
        .governance
        .velocity_tracker
        .aggregate_velocity(now_secs);
    let metrics = ObservableMetrics {
        sender_velocity: velocity,
        member_count,
        context_message_rate: aggregate,
        relay_queue_depth: 0,
        time_of_day: now_secs % 86400,
        storage_usage: 0,
    };

    let economic_policy = state.governance.economic_policy.clone();
    let consequence_rules = state.governance.consequence_rules.clone();
    let message_pricing = state.governance.message_pricing.clone();

    let events_snapshot = crate::context::governance_logic::event_log_entries_for_consequences(
        &state.receive_buffer,
        context_id,
        now_secs,
        event_log.as_ref(),
    );

    let mut participation_cache: HashMap<
        String,
        scp_protocol::trust::participation::ParticipationRecord,
    > = HashMap::new();

    let action_cost = {
        let economy = ToolEconomyContext {
            economic_policy: economic_policy.as_ref(),
            budget_tracker: &mut state.governance.budget_tracker,
            spending_ucan,
            context_id,
            now: now_secs,
            events: &events_snapshot,
            participation_cache: &mut participation_cache,
            consequence_rules: &consequence_rules,
            payment_adapter: payment_adapter.clone(),
            metrics: metrics.clone(),
            velocity_tracker: Some(&state.governance.velocity_tracker),
            message_pricing: message_pricing.as_ref(),
        };

        match economy_pre_check(&economy, invoker_did) {
            Ok(cost) => cost,
            Err(err) => {
                state
                    .governance
                    .velocity_tracker
                    .rollback(invoker_did, velocity_token);
                state.governance.hard_rate_limit.refund(invoker_did);
                return Err(invocation_error_to_context(err));
            }
        }
    };

    if action_cost.0 > 0 {
        let Some(spending) = spending_ucan else {
            state
                .governance
                .velocity_tracker
                .rollback(invoker_did, velocity_token);
            state.governance.hard_rate_limit.refund(invoker_did);
            return Err(ContextError::PermissionDenied(
                "SCP-ECON-12060: paid action requires spending UCAN".to_owned(),
            ));
        };
        if let Err(err) = crate::context::economy_logic::validate_spending_ucan_or_error(
            spending,
            invoker_did,
            context_id,
            &mut state.governance.spending_nonce_tracker,
            &state.governance.revoked_spending_ucan_cids,
            key_resolver,
            clock,
        ) {
            state
                .governance
                .velocity_tracker
                .rollback(invoker_did, velocity_token);
            state.governance.hard_rate_limit.refund(invoker_did);
            return Err(err);
        }
    }

    let deducted_cost = if action_cost.0 > 0 {
        if state
            .governance
            .budget_tracker
            .record_spend(invoker_did, action_cost)
            .is_err()
        {
            let remaining = state.governance.budget_tracker.remaining(invoker_did).0;
            state
                .governance
                .velocity_tracker
                .rollback(invoker_did, velocity_token);
            state.governance.hard_rate_limit.refund(invoker_did);
            return Err(invocation_error_to_context(
                InvocationError::BudgetExceeded {
                    did: invoker_did.to_string(),
                    cost: action_cost.0,
                    remaining,
                },
            ));
        }
        Some(action_cost)
    } else {
        None
    };

    if deducted_cost.is_some()
        && let Some(spending) = spending_ucan
        && let Err(e) = scp_protocol::crypto::ucan::spending::commit_spending_ucan_nonce(
            spending,
            &mut state.governance.spending_nonce_tracker,
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
        state.governance.hard_rate_limit.refund(invoker_did);
        return Err(ContextError::PermissionDenied(format!(
            "SCP-ECON-12066: nonce commit failed after budget acceptance: {e}"
        )));
    }

    // ADR-049 §9 Class S: the spending-nonce consume is security-critical
    // monotonic state that does NOT survive an actor crash (it lives in the
    // actor-owned `spending_nonce_tracker`). It MUST be durably persisted
    // BEFORE this reservation is acknowledged to the caller — otherwise an
    // actor crash in the ≤50ms coalesce window would roll the consume back,
    // letting the same spending UCAN nonce be replayed after the caller already
    // saw the spend succeed. Persist fail-closed: on a persist failure, reverse
    // the budget/velocity/rate-limit reservation and return an error so the
    // operation is NOT acknowledged. (The consumed nonce is intentionally NOT
    // un-consumed — leaving it consumed is the conservative/fail-closed
    // direction for replay protection; un-consuming would re-open the replay
    // window, the exact failure this guard prevents.)
    if deducted_cost.is_some()
        && spending_ucan.is_some()
        && let Err(persist_err) =
            crate::context::messaging_helpers::persist_state_fail_closed(state, deps, context_id)
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
        state.governance.hard_rate_limit.refund(invoker_did);
        return Err(persist_err);
    }

    let escrow = match (economic_policy.as_ref(), payment_adapter.as_ref()) {
        (Some(policy), Some(adapter)) => {
            match invoke::authorize_tool_payment(
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
                    state.governance.hard_rate_limit.refund(invoker_did);
                    return Err(invocation_error_to_context(auth_err));
                }
            }
        }
        _ => None,
    };

    let ticket = ToolEconomyTicket {
        actor_did: invoker_did.clone(),
        deducted_cost,
        velocity_token,
        escrow,
        policy_for_capture: economic_policy,
        metrics_for_capture: metrics,
        needs_hard_rate_limit_refund: true,
        consumed: false,
    };

    Ok(ToolEconomyReservation {
        handle,
        role_state,
        generation: state.generation,
        ticket,
    })
}

// ---------------------------------------------------------------------------
// Phase 3a: settle_tool_economy_capture (actor handler entry point)
// ---------------------------------------------------------------------------

/// Phase 3 of the tool economy pipeline on executor SUCCESS, run inside
/// the per-context actor on owned state. Performs post-invocation
/// participation bookkeeping + consequence enforcement, then captures the
/// escrowed payment, and finally commits the ticket.
///
/// Returns the triggered consequences and the optional payment receipt.
/// On payment-capture failure the ticket is reversed (budget / velocity /
/// rate-limit) and the error surfaced.
///
/// # Errors
///
/// Propagates [`ContextError::PermissionDenied`] when payment capture
/// fails after a successful execution.
pub async fn settle_tool_economy_capture(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    invoker_did: &DID,
    ticket: ToolEconomyTicket,
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
    let events_for_consequences =
        crate::context::governance_logic::event_log_entries_for_consequences(
            &state.receive_buffer,
            context_id,
            now,
            event_log.as_ref(),
        );
    let consequence_rules = state.governance.consequence_rules.clone();

    let consequences = post_tool_invocation_bookkeeping(
        &events_for_consequences,
        invoker_did,
        context_id,
        now,
        &mut state.governance.participation_cache,
        &consequence_rules,
    );

    let mut split = crate::context::governance_logic::ConsequenceStateSplit::from_state(state);
    crate::context::governance_logic::enforce_triggered_consequences(
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
    );

    let payment_receipt = match (
        payment_adapter.as_ref(),
        ticket.escrow.as_ref(),
        ticket.policy_for_capture.as_ref(),
    ) {
        (Some(adapter), Some(prepared), policy_opt) => {
            match invoke::complete_tool_payment(
                adapter.as_ref(),
                policy_opt,
                prepared,
                &ticket.metrics_for_capture,
            )
            .await
            {
                Ok(receipt) => receipt,
                Err(capture_err) => {
                    if let Some(cost) = ticket.deducted_cost {
                        state
                            .governance
                            .budget_tracker
                            .reverse_spend(invoker_did, cost);
                    }
                    state
                        .governance
                        .velocity_tracker
                        .rollback(invoker_did, ticket.velocity_token);
                    if ticket.needs_hard_rate_limit_refund {
                        state.governance.hard_rate_limit.refund(invoker_did);
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

    let _cost = commit_tool_economy_ticket(ticket);
    Ok((consequences, payment_receipt))
}

// ---------------------------------------------------------------------------
// Phase 3b: rollback_tool_economy (actor handler entry point)
// ---------------------------------------------------------------------------

/// Phase 3 of the tool economy pipeline on executor FAILURE, run inside
/// the per-context actor on owned state. Voids any payment escrow hold,
/// then reverses the velocity entry, budget deduction, and hard-rate-limit
/// token consumed by [`reserve_tool_economy`].
/// Generation-checked Phase-3 rollback. Reverses the reservation against THIS
/// actor's owned state ONLY if the reservation's `generation` still matches the
/// live actor's `state.generation`; on a MISMATCH the actor was despawned and a
/// new instance respawned for the same `context_id` between reserve and this
/// rollback (e.g. an import replace), so refunding velocity / budget /
/// hard-rate-limit against THIS instance's owned state would be a
/// confused-deputy write to the WRONG context instance. On mismatch it voids
/// only the EXTERNAL escrow (the real payment hold the prior instance authorized
/// at reserve) and consumes the ticket — exactly mirroring
/// [`settle_tool_economy`]'s generation guard, but for the failure/abort path.
///
/// This is the rollback-path counterpart the saga abort handler and the
/// Commit-A idempotency-replay branch use: those paths previously called
/// [`rollback_tool_economy`] directly, which writes local state
/// unconditionally and would corrupt a respawned (gen N→N+1) instance's economy
/// state. Returns `true` when the local rollback ran (generations matched),
/// `false` when only the external escrow was voided (mismatch).
pub async fn rollback_tool_economy_generation_checked(
    state: &mut PerContextState,
    deps: &ActorDeps,
    reservation_generation: u64,
    ticket: ToolEconomyTicket,
) -> bool {
    if reservation_generation != state.generation {
        // Confused-deputy guard (mirrors `settle_tool_economy`): the reservation
        // belongs to a now-replaced actor instance. Void only the external
        // escrow and consume; the context-local bookkeeping lived in the gone
        // instance's `PerContextState` and must NOT be touched here.
        ticket
            .void_external_and_consume(deps.payment_adapter.as_ref())
            .await;
        return false;
    }
    rollback_tool_economy(state, deps, ticket).await;
    true
}

pub async fn rollback_tool_economy(
    state: &mut PerContextState,
    deps: &ActorDeps,
    mut ticket: ToolEconomyTicket,
) {
    ticket.consumed = true;

    if let (Some(adapter), Some(prepared)) = (deps.payment_adapter.as_ref(), ticket.escrow.as_ref())
    {
        invoke::void_tool_escrow(adapter.as_ref(), prepared).await;
    }

    state
        .governance
        .velocity_tracker
        .rollback(&ticket.actor_did, ticket.velocity_token);
    if let Some(cost) = ticket.deducted_cost {
        state
            .governance
            .budget_tracker
            .reverse_spend(&ticket.actor_did, cost);
    }
    if ticket.needs_hard_rate_limit_refund {
        state.governance.hard_rate_limit.refund(&ticket.actor_did);
        ticket.needs_hard_rate_limit_refund = false;
    }
}

// ---------------------------------------------------------------------------
// Supervisor-side orchestrator: invoke_tool_with_economy
// ---------------------------------------------------------------------------

/// Invokes a tool under the full economy pipeline without holding any
/// per-context lock across the executor future (spec §19.7), in the
/// actor model.
///
/// Orchestrates the three-phase split: dispatch the Phase-1
/// [`ToolsCommand::ReserveToolEconomy`](crate::context::actor::commands::ToolsCommand::ReserveToolEconomy)
/// to the context actor (economy reserve on owned state), run the
/// non-`Send` executor supervisor-side via
/// [`invoke_tool_execute_and_validate`], then dispatch the Phase-3
/// [`ToolsCommand::SettleToolEconomy`](crate::context::actor::commands::ToolsCommand::SettleToolEconomy)
/// (capture on success / rollback on failure). The economy bookkeeping
/// never crosses the mailbox as anything but a `Send`
/// [`ToolEconomyReservation`]; the executor never crosses the mailbox at
/// all.
///
/// `reserve` / `settle` are caller-supplied closures that perform the
/// mailbox round-trips (the supervisor owns the actor registry and the
/// command-construction surface); this keeps `tools_helpers` free of a
/// `&Supervisor` dependency while concentrating the lock-split sequencing
/// in one place.
///
/// # Errors
///
/// Propagates every error variant the reserve / settle handlers and the
/// executor emit (`ContextNotRegistered`, `PermissionDenied`,
/// `RateLimited`, schema/economy/UCAN failures).
// Mirrors the FFI tool-invocation surface (registry/tool_id/input/
// invoker_did/timeout_ms/executor) plus the two phase-handoff closures;
// bundling them would only obscure the lock-split sequencing.
#[allow(clippy::too_many_arguments)]
pub async fn invoke_tool_with_economy<Reserve, ReserveFut, Settle, SettleFut, F, Fut>(
    registry: &ToolRegistry,
    tool_id: &ToolId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    reserve: Reserve,
    settle: Settle,
    executor: F,
) -> Result<ManagedToolInvocationOutput, ContextError>
where
    Reserve: FnOnce() -> ReserveFut,
    ReserveFut: Future<Output = Result<ToolEconomyReservation, ContextError>>,
    Settle: FnOnce(ToolSettleRequest) -> SettleFut,
    SettleFut: Future<Output = Result<ToolSettleOutcome, ContextError>>,
    F: FnOnce(serde_json::Value) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
{
    // Phase 1 — economy reserve runs inside the actor on owned state.
    let ToolEconomyReservation {
        handle,
        role_state,
        generation,
        ticket,
    } = reserve().await?;

    // Phase 2 — run the non-Send executor supervisor-side, OFF the actor
    // mailbox, so the actor is free to process other commands and a
    // misbehaving tool cannot stall the per-context actor loop.
    let outcome = match invoke_tool_execute_and_validate(
        &handle,
        registry,
        &role_state,
        tool_id,
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
            // `settle_tool_economy_via_actor`), but we still surface the
            // failure to logs — a settle that cannot run is an economy
            // anomaly the operator must see.
            if let Err(settle_err) =
                settle(ToolSettleRequest::Rollback { generation, ticket }).await
            {
                tracing::error!(
                    rollback_error = %settle_err,
                    executor_error = %err,
                    "tool-economy rollback settle failed after executor error; the settle \
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
    let ToolSettleOutcome {
        consequences,
        payment_receipt,
        cost,
    } = settle(ToolSettleRequest::Capture { generation, ticket }).await?;

    let event = build_tool_event(
        tool_id,
        invoker_did,
        execution_time_ms,
        input_hash,
        output_hash,
        cost,
    );

    Ok(ManagedToolInvocationOutput {
        output,
        event,
        consequences,
        payment_receipt,
    })
}

/// Phase-3 settle request handed to the supervisor-supplied `settle`
/// closure by [`invoke_tool_with_economy`], and carried into the actor
/// via [`ToolsCommand::SettleToolEconomy`](crate::context::actor::commands::ToolsCommand::SettleToolEconomy).
#[derive(Debug)]
pub enum ToolSettleRequest {
    /// Executor succeeded — capture payment + run post-invocation
    /// bookkeeping.
    Capture {
        /// Spawn-generation of the actor instance the reservation was
        /// made against. The settle handler rejects if the live actor's
        /// generation no longer matches.
        generation: u64,
        /// The in-flight economy ticket from Phase 1.
        ticket: ToolEconomyTicket,
    },
    /// Executor failed — void escrow + reverse budget / velocity /
    /// rate-limit.
    Rollback {
        /// Spawn-generation of the actor instance the reservation was
        /// made against. The settle handler rejects if the live actor's
        /// generation no longer matches.
        generation: u64,
        /// The in-flight economy ticket from Phase 1.
        ticket: ToolEconomyTicket,
    },
}

impl ToolSettleRequest {
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
    pub fn into_ticket(self) -> ToolEconomyTicket {
        match self {
            Self::Capture { ticket, .. } | Self::Rollback { ticket, .. } => ticket,
        }
    }
}

/// Phase-3 capture outcome returned by the supervisor-supplied `settle`
/// closure to [`invoke_tool_with_economy`].
#[derive(Debug, Default)]
pub struct ToolSettleOutcome {
    /// Consequences triggered by the invocation.
    pub consequences: Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
    /// Payment receipt when a payment adapter is configured.
    pub payment_receipt: Option<PaymentReceipt>,
    /// Committed action cost for inclusion in the `ToolInvokedEvent`.
    pub cost: Option<Amount>,
}

/// Single Phase-3 settle entry point for the actor
/// [`SettleToolEconomy`](crate::context::actor::commands::ToolsCommand::SettleToolEconomy)
/// handler. Dispatches the request to
/// [`settle_tool_economy_capture`] (success) or [`rollback_tool_economy`]
/// (failure) on owned state and assembles the [`ToolSettleOutcome`].
///
/// # Errors
///
/// Propagates the capture path's [`ContextError`] on payment-capture
/// failure. The rollback path is infallible.
pub async fn settle_tool_economy(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    invoker_did: &DID,
    request: ToolSettleRequest,
) -> Result<ToolSettleOutcome, ContextError> {
    // Confused-deputy guard: the reservation was made against a specific
    // actor-instance generation. If this actor's generation differs, the
    // original instance was despawned and a NEW instance respawned for
    // the same `context_id` between reserve and settle (e.g. an import
    // replace). Capturing or refunding against THIS instance's owned
    // budget / velocity / rate-limit would corrupt the wrong context's
    // economy state. Reject without touching this state — void only the
    // EXTERNAL escrow (a real payment hold from the prior instance's
    // reserve) and consume the ticket so it does not leak or trip the
    // unbalanced-Drop guard.
    if request.generation() != state.generation {
        let expected = request.generation();
        let actual = state.generation;
        let ticket = request.into_ticket();
        ticket
            .void_external_and_consume(deps.payment_adapter.as_ref())
            .await;
        return Err(ContextError::ContextNotRegistered(format!(
            "SCP-TOOL-6088: tool-economy settle for context '{context_id}' landed on a replaced \
             actor instance (reserved generation {expected}, live generation {actual}); escrow \
             voided, reservation not captured"
        )));
    }

    match request {
        ToolSettleRequest::Capture { ticket, .. } => {
            // Read the committed cost before the ticket is consumed by
            // the capture path so it can be threaded into the event.
            let cost = ticket.deducted_cost;
            let (consequences, payment_receipt) =
                settle_tool_economy_capture(state, deps, context_id, invoker_did, ticket).await?;
            Ok(ToolSettleOutcome {
                consequences,
                payment_receipt,
                cost,
            })
        }
        ToolSettleRequest::Rollback { ticket, .. } => {
            rollback_tool_economy(state, deps, ticket).await;
            Ok(ToolSettleOutcome::default())
        }
    }
}

fn invocation_error_to_context(err: InvocationError) -> ContextError {
    match err {
        InvocationError::ContextNotActive { current_state } => ContextError::PermissionDenied(
            format!("SCP-TOOL-6080: context not active: {current_state}"),
        ),
        InvocationError::InvokerNotAuthorized { did, tool_id } => ContextError::PermissionDenied(
            format!("SCP-TOOL-6081: invoker {did} lacks ToolInvoke({tool_id})"),
        ),
        InvocationError::ToolNotFound { tool_id } => {
            ContextError::PermissionDenied(format!("SCP-TOOL-6082: tool not found: {tool_id}"))
        }
        InvocationError::InputValidationFailed { message } => ContextError::PermissionDenied(
            format!("SCP-TOOL-6083: input schema validation failed: {message}"),
        ),
        InvocationError::OutputValidationFailed { message } => ContextError::PermissionDenied(
            format!("SCP-TOOL-6084: output schema validation failed: {message}"),
        ),
        InvocationError::ExecutionFailed { message } => ContextError::PermissionDenied(format!(
            "SCP-TOOL-6085: tool execution failed: {message}"
        )),
        InvocationError::Timeout { timeout_ms } => ContextError::PermissionDenied(format!(
            "SCP-TOOL-6086: tool execution timed out after {timeout_ms}ms"
        )),
        InvocationError::Cancelled => {
            ContextError::PermissionDenied("SCP-TOOL-6087: tool invocation cancelled".to_owned())
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

    fn test_did() -> DID {
        DID::from("did:test:tools-rate-limit")
    }

    fn test_admin() -> DID {
        DID::from("did:test:admin")
    }

    #[test]
    fn consume_hard_rate_limit_uses_actor_owned_state() {
        let did = test_did();
        let mut state = PerContextState::new_for_test_encrypted([9u8; 32], 1, test_admin());

        assert!(try_consume_hard_rate_limit(&mut state, &did, 10));
    }

    #[test]
    fn refund_hard_rate_limit_restores_actor_owned_bucket() {
        let did = test_did();
        let mut state = PerContextState::new_for_test_encrypted([10u8; 32], 1, test_admin());

        for _ in 0..10 {
            assert!(try_consume_hard_rate_limit(&mut state, &did, 10));
        }
        assert!(!try_consume_hard_rate_limit(&mut state, &did, 10));
        refund_hard_rate_limit(&mut state, &did);
        assert!(try_consume_hard_rate_limit(&mut state, &did, 10));
    }

    fn ticket_with_budget(did: &DID) -> ToolEconomyTicket {
        ToolEconomyTicket::new_for_test_no_escrow(did.clone())
    }

    /// `ToolSettleRequest::generation()` reports the reservation's
    /// generation for both variants, and `into_ticket()` hands the inner
    /// ticket back so the orchestrator can reverse it on an unreachable
    /// settle.
    #[test]
    fn settle_request_exposes_generation_and_ticket() {
        let did = test_did();

        let capture = ToolSettleRequest::Capture {
            generation: 42,
            ticket: ticket_with_budget(&did),
        };
        assert_eq!(capture.generation(), 42);
        // Consume the reclaimed ticket so its Drop balance guard does not
        // fire (no escrow ⇒ pure consume).
        capture.into_ticket().consume_abandoning_escrow();

        let rollback = ToolSettleRequest::Rollback {
            generation: 7,
            ticket: ticket_with_budget(&did),
        };
        assert_eq!(rollback.generation(), 7);
        rollback.into_ticket().consume_abandoning_escrow();
    }

    /// The unreachable-actor reversal path
    /// (`ToolEconomyTicket::void_external_and_consume`) must consume the
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
}
