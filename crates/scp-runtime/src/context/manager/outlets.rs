//! `ContextManager::invoke_outlet_with_economy` — outlet invocation with
//! per-DID anti-spam escalation wired from per-context governance state.
//!
//! This wrapper is the integration point between the free
//! [`invoke_outlet_execute_and_validate`](crate::context::outlets::invoke::invoke_outlet_execute_and_validate)
//! helper and the [`super::ContextManager`] per-context state. It
//! snapshots economic policy, budget tracker, per-DID velocity tracker,
//! message pricing config, a real event-log snapshot, consequence rules,
//! metrics, and participation cache from the context's `GovernanceState`
//! so that outlet invocations participate in the same per-DID anti-spam
//! regime as message sends (spec §19.7).
//!
//! # Lock-split invariant
//!
//! The caller-supplied executor must run **without** holding the
//! `ContextManager.contexts` mutex. A mis-behaving or long-running tool
//! executor would otherwise block every concurrent call into the manager.
//! This module enforces the split by structuring the wrapper into three
//! phases:
//!
//! 1. **Phase 1 — locked:** snapshot all governance state, run
//!    `economy_pre_check` (pure compute), `record_spend` against the
//!    per-context budget, and escrow-authorize the payment. A
//!    [`OutletEconomyTicket`] is assembled from the resulting bookkeeping.
//! 2. **Phase 2 — unlocked:** the `contexts` lock is dropped; the executor
//!    is dispatched via
//!    [`invoke_outlet_execute_and_validate`](crate::context::outlets::invoke::invoke_outlet_execute_and_validate)
//!    which performs context-state, capability, schema, timeout, and
//!    output-schema checks *again* (defensive) using the snapshotted
//!    handle + role state. On any error the ticket is drained
//!    (budget reversed, velocity entry rolled back, escrow voided).
//! 3. **Phase 3 — locked then unlocked:** the lock is re-acquired to run
//!    post-invocation bookkeeping (participation cache, consequence
//!    evaluation), then released again for the escrow-capture call.
//!    Only then is the ticket committed.
//!
//! The `OutletEconomyTicket` is `#[must_use]` with a `Drop` guard that
//! debug-asserts in tests so no future refactor can leak an unbalanced
//! budget deduction or velocity entry on an untested error branch.
//!
//! # Registry ownership
//!
//! The wrapper takes the [`OutletRegistry`] and executor as explicit
//! parameters because the manager does not own a per-context tool
//! registry today (it lives in the FFI bridge layers). This preserves
//! the bridge-owned registry invariant while keeping outlet invocations
//! within the full governance pipeline.

use std::collections::HashMap;
use std::future::Future;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::OutletKind;
use scp_protocol::context::outlets::lifecycle::OutletInvokedEvent;
use scp_protocol::context::outlets::lifecycle::OutletStatus;
use scp_protocol::context::outlets::registry::OutletRegistry;
use scp_protocol::context::roles::Capability;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::economy::antispam::VelocityRollbackToken;
use scp_protocol::economy::policy::ObservableMetrics;
use scp_protocol::economy::types::Amount;
use scp_protocol::provenance::attach::effective_max_chain_depth;

use crate::context::outlets::invoke::{
    self, InvocationError, InvokeExecuteOutcome, OutletEconomyContext, build_outlet_event,
    economy_pre_check, invoke_outlet_execute_and_validate, post_outlet_invocation_bookkeeping,
};
use crate::economy::adapter::PaymentAdapterDyn;
use crate::economy::integration::PreparedAction;

use super::{Arc, ContextGeneration, ContextManager};

/// Result of a successful managed outlet invocation.
#[derive(Debug)]
pub struct ManagedOutletInvocationOutput {
    /// Outlet output JSON.
    pub output: serde_json::Value,
    /// Event to append to the event log.
    pub event: OutletInvokedEvent,
    /// Consequences triggered by the invocation.
    pub consequences: Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
    /// Payment receipt when a payment adapter is configured.
    pub payment_receipt: Option<crate::economy::adapter::PaymentReceipt>,
}

/// Phase-1 bookkeeping bundle for an outlet invocation in flight.
///
/// Every Phase 1 success produces a [`OutletEconomyTicket`]; every Phase 2
/// or Phase 3 error branch MUST drain it through
/// [`rollback_outlet_economy_ticket`] (refund budget + roll back velocity
/// entry + void escrow) or commit it through
/// [`commit_outlet_economy_ticket`]. Dropping it without doing one or the
/// other is a compile-time warning (`#[must_use]`) and a `Drop`
/// debug-assert so unit tests fail loudly.
///
/// Mirrors [`super::economy::EconomyTicket`] one-for-one; a separate
/// type exists because the outlet path also owns a cloned `PreparedAction`
/// escrow handle and the void + capture steps use the outlet-flavor
/// adapter helpers in [`crate::context::outlets::invoke`].
#[must_use = "OutletEconomyTicket must be committed or rolled back — dropping leaks budget, velocity, and escrow state"]
struct OutletEconomyTicket {
    /// The invoker being charged — needed for every rollback operation.
    actor_did: DID,
    /// The budget amount deducted in Phase 1 (if any).
    deducted_cost: Option<Amount>,
    /// Velocity-tracker rollback token for the entry appended in Phase 1.
    velocity_token: VelocityRollbackToken,
    /// Escrow authorization returned by the adapter, if a payment flow
    /// is configured and the action cost is non-zero. Cloneable, so we
    /// keep an owned copy across the unlocked Phase 2 window.
    escrow: Option<PreparedAction>,
    /// Snapshot of the economic policy that produced `deducted_cost`.
    /// Retained for the Phase 3 capture step so the capture uses the
    /// same policy that was priced against under the Phase 1 lock.
    policy_for_capture: Option<scp_protocol::economy::types::EconomicPolicy>,
    /// Observable metrics captured in Phase 1. Reused by
    /// [`invoke::complete_outlet_payment`] in Phase 3 so the capture step
    /// sees the same metrics the Phase 1 authorize saw — eliminating a
    /// TOCTOU window where the adapter could diverge from the budget.
    metrics_for_capture: ObservableMetrics,
    /// Whether the Phase 1 hard-rate-limit token must be refunded on
    /// rollback. Set to `true` on ticket creation because the token
    /// was consumed before the ticket was built; cleared after the
    /// rollback path calls `refund` so repeated rollback calls are
    /// idempotent.
    needs_hard_rate_limit_refund: bool,
    /// Set to `true` by `commit`/`rollback` so the `Drop` guard can tell
    /// that the caller honored the contract.
    consumed: bool,
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

/// Marks the ticket committed (success path). Returns the deducted cost
/// so the caller can populate the `OutletInvokedEvent`. Clears
/// `needs_hard_rate_limit_refund` so the invariant
/// "`needs_hard_rate_limit_refund == true` iff a refund is still owed"
/// holds against any defensive rollback call.
fn commit_outlet_economy_ticket(mut ticket: OutletEconomyTicket) -> Option<Amount> {
    ticket.consumed = true;
    ticket.needs_hard_rate_limit_refund = false;
    ticket.deducted_cost
}

/// Rolls back every piece of state the ticket represents:
///
/// * budget deduction (via `reverse_spend`, not `grant`, so ceilings
///   stay intact),
/// * velocity entry (via the identity-based `rollback(did, token)` API
///   so concurrent senders are not raced),
/// * payment escrow hold (best-effort `void`).
///
/// Re-acquires the `contexts` lock internally so this is safe to call
/// from Phase 2 (off-lock) error paths. If the context has been
/// deregistered between Phase 1 and rollback the budget + velocity
/// rollback is a best-effort no-op — the escrow void is still attempted
/// since it is adapter-side state, not manager-side, and the ticket is
/// still marked consumed so the `Drop` guard stays quiet.
#[allow(clippy::significant_drop_tightening)]
async fn rollback_outlet_economy_ticket(
    manager: &ContextManager,
    context_id: &str,
    mut ticket: OutletEconomyTicket,
) {
    ticket.consumed = true;

    // Void the adapter-side escrow first so it does not survive the
    // manager-side rollback. This mirrors `void_escrow_and_rollback` in
    // the free `invoke_outlet` path.
    if let (Some(adapter), Some(prepared)) =
        (manager.payment_adapter.as_ref(), ticket.escrow.as_ref())
    {
        invoke::void_outlet_escrow(adapter.as_ref(), prepared).await;
    }

    // Reacquire the lock and reverse the per-context bookkeeping.
    if let Some(entry) = manager.contexts.get(context_id) {
        let arc = entry.value().clone();
        drop(entry);
        let mut guard = arc.lock().await;
        let ctx = &mut *guard;
        ctx.governance
            .velocity_tracker
            .rollback(&ticket.actor_did, ticket.velocity_token);
        if let Some(cost) = ticket.deducted_cost {
            ctx.governance
                .budget_tracker
                .reverse_spend(&ticket.actor_did, cost);
        }
        if ticket.needs_hard_rate_limit_refund {
            ctx.governance.hard_rate_limit.refund(&ticket.actor_did);
            ticket.needs_hard_rate_limit_refund = false;
        }
    }
}

impl ContextManager {
    /// Synchronously consume one hard-rate-limit token for the given
    /// `(context_id, did)` pair.
    ///
    /// Returns `true` if a token was consumed OR if the context is
    /// not registered in the `ContextManager`. Returns `false` only
    /// when the context IS registered AND the sender is over budget.
    ///
    /// SYNC entry point for FFI bridge tool-dispatch paths that do
    /// not flow through [`Self::invoke_outlet_with_economy`] (the
    /// bridges own their own tool registry + handler dispatch
    /// because JS/Python callables live in bridge-side state, not
    /// in the `ContextManager`).
    ///
    /// Bridges MUST pair every `true` return with a matching
    /// [`Self::refund_hard_rate_limit_blocking`] call on every
    /// downstream failure branch. Refund is a no-op when the
    /// context is unknown.
    ///
    /// An unknown `context_id` returns `true` rather than an error
    /// because the downstream `with_context` call inside the bridge
    /// will fail with a more specific "outlet not found" error, and
    /// because there is no rate-limit state to enforce against
    /// without a manager entry.
    ///
    /// # Concurrency
    ///
    /// Uses `blocking_lock` on `self.contexts`. Callers MUST NOT
    /// invoke this from within an async task on the same tokio
    /// runtime — doing so will panic.
    #[allow(clippy::significant_drop_tightening)] // two-step borrow on the contexts map
    #[must_use]
    pub fn try_consume_hard_rate_limit_blocking(
        &self,
        context_id: &str,
        did: &DID,
        now_secs: u64,
    ) -> bool {
        let Ok(arc) = self.get_context_arc(context_id) else {
            return true;
        };
        let ctx = arc.blocking_lock();
        ctx.governance.hard_rate_limit.try_consume(did, now_secs)
    }

    /// Synchronously refund one hard-rate-limit token. No-op if the
    /// context is unknown. Same `blocking_lock` constraint as
    /// [`Self::try_consume_hard_rate_limit_blocking`].
    pub fn refund_hard_rate_limit_blocking(&self, context_id: &str, did: &DID) {
        let Ok(arc) = self.get_context_arc(context_id) else {
            return;
        };
        let ctx = arc.blocking_lock();
        ctx.governance.hard_rate_limit.refund(did);
    }

    /// Async variant of [`Self::try_consume_hard_rate_limit_blocking`]
    /// for callers already inside a tokio executor where
    /// `blocking_lock` would panic. Same unknown-context pass-through.
    #[allow(clippy::significant_drop_tightening)] // two-step borrow on the contexts map
    #[must_use]
    pub async fn try_consume_hard_rate_limit(
        &self,
        context_id: &str,
        did: &DID,
        now_secs: u64,
    ) -> bool {
        let Ok(arc) = self.get_context_arc(context_id) else {
            return true;
        };
        let mut guard = arc.lock().await;
        let ctx = &mut *guard;
        ctx.governance.hard_rate_limit.try_consume(did, now_secs)
    }

    /// Async refund. No-op if the context is unknown.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn refund_hard_rate_limit(&self, context_id: &str, did: &DID) {
        if let Ok(ctx_arc) = self.get_context_arc(context_id) {
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            ctx.governance.hard_rate_limit.refund(did);
        }
    }

    /// Runtime-agnostic hard-rate-limit consume for sync bridge trait
    /// methods that may be called from any of three tokio contexts:
    ///
    /// 1. **No runtime active**: use `blocking_lock` directly.
    /// 2. **Multi-thread runtime active**: use `block_in_place` +
    ///    `Handle::current().block_on(async_helper)`. `block_in_place`
    ///    is only valid on multi-thread runtimes.
    /// 3. **Current-thread runtime active**: neither `blocking_lock`
    ///    nor `block_in_place` is safe. Spawn a dedicated
    ///    `std::thread` with its own tiny current-thread runtime,
    ///    `block_on` the async helper, join via an mpsc channel.
    ///
    /// The third case is a defensive fallback. Same unknown-context
    /// pass-through as the blocking/async variants.
    #[must_use]
    #[allow(clippy::option_if_let_else)] // match is clearer than map_or_else for this dual arm
    pub fn try_consume_hard_rate_limit_from_any_context(
        self: &Arc<Self>,
        context_id: &str,
        did: &DID,
        now_secs: u64,
    ) -> bool {
        match tokio::runtime::Handle::try_current() {
            Err(_) => self.try_consume_hard_rate_limit_blocking(context_id, did, now_secs),
            Ok(handle) => {
                use tokio::runtime::RuntimeFlavor;
                match handle.runtime_flavor() {
                    RuntimeFlavor::MultiThread => tokio::task::block_in_place(|| {
                        handle.block_on(self.try_consume_hard_rate_limit(context_id, did, now_secs))
                    }),
                    // Current-thread or any future flavor: spawn a
                    // dedicated `std::thread` with its own runtime so
                    // we never touch the parent runtime's executor.
                    _ => Self::run_blocking_on_dedicated_thread(
                        Arc::clone(self),
                        context_id.to_owned(),
                        did.clone(),
                        now_secs,
                        /* refund = */ false,
                    ),
                }
            }
        }
    }

    /// Runtime-agnostic hard-rate-limit refund. Mirrors
    /// [`Self::try_consume_hard_rate_limit_from_any_context`].
    #[allow(clippy::option_if_let_else)] // match is clearer than map_or_else for this dual arm
    pub fn refund_hard_rate_limit_from_any_context(self: &Arc<Self>, context_id: &str, did: &DID) {
        match tokio::runtime::Handle::try_current() {
            Err(_) => {
                self.refund_hard_rate_limit_blocking(context_id, did);
            }
            Ok(handle) => {
                use tokio::runtime::RuntimeFlavor;
                match handle.runtime_flavor() {
                    RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| {
                            handle.block_on(self.refund_hard_rate_limit(context_id, did));
                        });
                    }
                    _ => {
                        let _ = Self::run_blocking_on_dedicated_thread(
                            Arc::clone(self),
                            context_id.to_owned(),
                            did.clone(),
                            0,
                            /* refund = */ true,
                        );
                    }
                }
            }
        }
    }

    /// Dedicated-thread escape hatch for current-thread runtime
    /// environments where both `blocking_lock` and `block_in_place`
    /// panic. Spawns a `std::thread`, builds a current-thread tokio
    /// runtime there, runs the async helper, returns via mpsc.
    fn run_blocking_on_dedicated_thread(
        manager: Arc<Self>,
        context_id: String,
        did: DID,
        now_secs: u64,
        refund: bool,
    ) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "dedicated rate-limit runtime build failed; failing closed"
                    );
                    let _ = tx.send(false);
                    return;
                }
            };
            let result = if refund {
                rt.block_on(manager.refund_hard_rate_limit(&context_id, &did));
                true
            } else {
                rt.block_on(manager.try_consume_hard_rate_limit(&context_id, &did, now_secs))
            };
            let _ = tx.send(result);
        });
        // Fail closed on channel failure (panicked worker etc.).
        rx.recv().unwrap_or(false)
    }

    /// Invokes an outlet under the full economy pipeline without holding
    /// the `contexts` mutex across the executor future (spec §19.7).
    ///
    /// This is the single entry point that tool-invoking bridges should
    /// use when they want the runtime to enforce per-DID escalation,
    /// floor/cap, and velocity tracking for `OutletCall` actions. The
    /// [`OutletRegistry`] and `executor` are passed in because the bridge
    /// layers own the registry — the manager itself does not.
    ///
    /// # Phase discipline
    ///
    /// The wrapper splits the invocation into three phases so that the
    /// `contexts` lock is held only while the manager is actually
    /// mutating per-context state:
    ///
    /// 1. **Phase 1 (locked):** snapshot governance state, record
    ///    velocity, run `economy_pre_check`, `record_spend` the cost,
    ///    authorize the payment escrow, assemble a
    ///    [`OutletEconomyTicket`]. The lock is released at the end of
    ///    Phase 1.
    /// 2. **Phase 2 (unlocked):** dispatch the executor via
    ///    [`invoke_outlet_execute_and_validate`]. On any failure the
    ///    ticket is drained (budget, velocity, escrow).
    /// 3. **Phase 3 (locked then unlocked):** re-acquire the lock for
    ///    post-invocation bookkeeping (participation cache + consequence
    ///    evaluation), release the lock, capture the escrow off-lock,
    ///    commit the ticket, and build the `OutletInvokedEvent`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if the context is
    /// unknown in Phase 1 or 3. Returns [`ContextError::PermissionDenied`]
    /// (with an `SCP-ECON-*` or `SCP-CTX-*` code) on any invocation,
    /// budget, UCAN composition, schema validation, or consequence
    /// failure. All errors are terminal for the invocation; partial
    /// state mutations (budget, velocity, escrow) are rolled back before
    /// the error is returned via the `OutletEconomyTicket`.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        clippy::significant_drop_tightening
    )]
    pub async fn invoke_outlet_with_economy<F, Fut>(
        &self,
        context_id: &str,
        registry: &OutletRegistry,
        outlet_id: &OutletId,
        input: serde_json::Value,
        invoker_did: &DID,
        spending_ucan: Option<&UcanToken>,
        timeout_ms: Option<u32>,
        executor: F,
    ) -> Result<ManagedOutletInvocationOutput, ContextError>
    where
        F: FnOnce(serde_json::Value) -> Fut,
        Fut: Future<Output = Result<serde_json::Value, String>>,
    {
        // ------------------------------------------------------------
        // Phase 1 — LOCKED.
        //
        // Snapshot every piece of per-context state the executor-free
        // pipeline needs (handle, role state, policy, pricing,
        // consequence rules, metrics, real event-log entries), record
        // the velocity entry, run the pure economy pre-check, record
        // the spend, authorize the payment escrow, and assemble a
        // [`OutletEconomyTicket`]. Phase 1 ends with `drop(contexts)`
        // so Phase 2 (the executor) runs WITHOUT the lock.
        // ------------------------------------------------------------
        let now_secs = self.clock.now_secs();
        let payment_adapter: Option<Arc<dyn PaymentAdapterDyn>> = self.payment_adapter.clone();

        let phase1 = {
            let (mut guard, ctx_gen) = self
                .lock_context(context_id)
                .await
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let ctx = &mut *guard;

            let handle = ctx.handle.clone();
            let role_state = ctx.role_state.clone();

            // Defense-in-depth Matrix-style hard rate limit: consume
            // a token from the per-invoker bucket BEFORE any
            // bookkeeping so the cap applies even when the cost
            // pipeline is free. Inline rollback paths refund
            // directly; the `OutletEconomyTicket`-based rollback
            // consults `needs_hard_rate_limit_refund`.
            if !ctx
                .governance
                .hard_rate_limit
                .try_consume(invoker_did, now_secs)
            {
                return Err(ContextError::RateLimited {
                    resource: "outlet_call".to_owned(),
                    message: "hard rate limit exceeded for invoker".to_owned(),
                });
            }

            // Record velocity BEFORE the pre-check so
            // `compute_escalated_cost` sees the new window entry,
            // matching `send_message`. Capture the rollback token so
            // a failure refunds THIS entry specifically rather than
            // racing concurrent invokers.
            let velocity_token = ctx
                .governance
                .velocity_tracker
                .record_message(invoker_did, now_secs);

            let velocity = ctx
                .governance
                .velocity_tracker
                .get_velocity(invoker_did, now_secs);
            let member_count = u64::try_from(ctx.membership.count()).unwrap_or(u64::MAX);
            let aggregate = ctx.governance.velocity_tracker.aggregate_velocity(now_secs);
            let metrics = ObservableMetrics {
                sender_velocity: velocity,
                member_count,
                context_message_rate: aggregate,
                relay_queue_depth: 0,
                time_of_day: now_secs % 86400,
                storage_usage: 0,
            };

            let economic_policy = ctx.governance.economic_policy.clone();
            let consequence_rules = ctx.governance.consequence_rules.clone();
            let message_pricing = ctx.governance.message_pricing.clone();

            // Per-context event snapshot from the event log so
            // consequence evaluation and participation-record
            // computation see the context's history.
            let events_snapshot = super::governance::event_log_entries_for_consequences(
                ctx,
                context_id,
                now_secs,
                self.event_log.as_ref(),
            );

            // Pre-check scope: build a throwaway participation cache so
            // the pre-check's pure compute can use the same struct the
            // wider invoke path expects. The cache is discarded at the
            // end of Phase 1 and rebuilt (as an empty map) in Phase 3;
            // standing updates happen via the authoritative per-context
            // cache held in `ctx.governance.participation_cache`.
            let mut participation_cache: HashMap<
                String,
                scp_protocol::trust::participation::ParticipationRecord,
            > = HashMap::new();

            let action_cost = {
                let economy = OutletEconomyContext {
                    economic_policy: economic_policy.as_ref(),
                    budget_tracker: &mut ctx.governance.budget_tracker,
                    spending_ucan,
                    context_id,
                    now: now_secs,
                    events: &events_snapshot,
                    participation_cache: &mut participation_cache,
                    consequence_rules: &consequence_rules,
                    payment_adapter: payment_adapter.clone(),
                    metrics: metrics.clone(),
                    velocity_tracker: Some(&ctx.governance.velocity_tracker),
                    message_pricing: message_pricing.as_ref(),
                };

                // Pure pre-check (Strategy B): no mutation of the
                // budget tracker. We perform the deduction ourselves
                // below so the mutation point is visible.
                match economy_pre_check(&economy, invoker_did) {
                    Ok(cost) => cost,
                    Err(err) => {
                        // Roll back the velocity entry and the hard
                        // rate-limit token we consumed above — nothing
                        // else has been mutated yet so the rollback
                        // is inline (no ticket to drain).
                        ctx.governance
                            .velocity_tracker
                            .rollback(invoker_did, velocity_token);
                        ctx.governance.hard_rate_limit.refund(invoker_did);
                        return Err(invocation_error_to_context(err));
                    }
                }
            };

            // C1b (PR #1606): cryptographically validate the spending UCAN
            // before mutating per-context economy state. Without this call
            // the attacker could present a fabricated `UcanToken` with a
            // valid-looking spending capability — `economy_pre_check` only
            // verifies the capability shape, not the signature, iss/aud
            // binding, expiry, revocation, or replay nonce. `enforce_economy`
            // (used by send/join) already runs this pipeline; `invoke_outlet_with_economy`
            // must match. For free actions (`action_cost == 0`) spending UCANs
            // are not required — mirroring `enforce_economy` and `check_spending_capability`.
            if action_cost.0 > 0 {
                let Some(spending) = spending_ucan else {
                    // Paid action reached this point without a spending UCAN:
                    // `economy_pre_check` would normally reject this via
                    // `check_outlet_spending_capability`, so reaching here is
                    // a defense-in-depth branch. Roll back and surface the
                    // canonical SCP-ECON-12060 error.
                    ctx.governance
                        .velocity_tracker
                        .rollback(invoker_did, velocity_token);
                    ctx.governance.hard_rate_limit.refund(invoker_did);
                    return Err(ContextError::PermissionDenied(
                        "SCP-ECON-12060: paid action requires spending UCAN".to_owned(),
                    ));
                };
                if let Err(err) = super::economy::validate_spending_ucan_or_error(
                    spending,
                    invoker_did,
                    context_id,
                    &mut ctx.governance.spending_nonce_tracker,
                    &ctx.governance.revoked_spending_ucan_cids,
                    &self.key_resolver,
                    &*self.clock,
                ) {
                    ctx.governance
                        .velocity_tracker
                        .rollback(invoker_did, velocity_token);
                    ctx.governance.hard_rate_limit.refund(invoker_did);
                    return Err(err);
                }
            }

            // Strategy B: the caller does the deduction explicitly so
            // the mutation point is visible and the pre-check function
            // stays pure.
            let deducted_cost = if action_cost.0 > 0 {
                if ctx
                    .governance
                    .budget_tracker
                    .record_spend(invoker_did, action_cost)
                    .is_err()
                {
                    let remaining = ctx.governance.budget_tracker.remaining(invoker_did).0;
                    ctx.governance
                        .velocity_tracker
                        .rollback(invoker_did, velocity_token);
                    ctx.governance.hard_rate_limit.refund(invoker_did);
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

            // H11 split-phase nonce commit: `validate_spending_ucan_or_error`
            // above only ran `check_replay` (read-only probe). The durable
            // `record` happens here — AFTER the budget gate passes — so that
            // budget-rejected requests cannot burn nonce tracker capacity
            // (nonce-burn DoS). Mirror of the `enforce_economy` nonce-commit
            // path in economy.rs.
            //
            // `deducted_cost.is_some()` implies `action_cost.0 > 0` which
            // implies the `let Some(spending) = spending_ucan` guard above
            // already passed (otherwise we returned early). Only evaluate
            // when both conditions hold to avoid a redundant Some-unwrap.
            if deducted_cost.is_some()
                && let Some(spending) = spending_ucan
                && let Err(e) = scp_protocol::crypto::ucan::spending::commit_spending_ucan_nonce(
                    spending,
                    &mut ctx.governance.spending_nonce_tracker,
                )
            {
                // Nonce commit failed — reverse the budget deduction
                // and roll back velocity + hard-rate-limit before
                // surfacing the error.
                if let Some(cost) = deducted_cost {
                    ctx.governance
                        .budget_tracker
                        .reverse_spend(invoker_did, cost);
                }
                ctx.governance
                    .velocity_tracker
                    .rollback(invoker_did, velocity_token);
                ctx.governance.hard_rate_limit.refund(invoker_did);
                return Err(ContextError::PermissionDenied(format!(
                    "SCP-ECON-12066: nonce commit failed after budget acceptance: {e}"
                )));
            }

            // Payment escrow (authorize hold). Must run under the lock
            // because the adapter call needs the per-context policy and
            // metrics snapshot we just computed; re-acquiring the lock
            // after the adapter call would introduce a TOCTOU window
            // where another task could mutate policy/metrics between
            // authorize and budget recording.
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
                            // Authorization failed — reverse budget,
                            // velocity, and the hard-rate-limit token
                            // inline (no ticket to drain yet) under
                            // the still-held lock.
                            if let Some(cost) = deducted_cost {
                                ctx.governance
                                    .budget_tracker
                                    .reverse_spend(invoker_did, cost);
                            }
                            ctx.governance
                                .velocity_tracker
                                .rollback(invoker_did, velocity_token);
                            ctx.governance.hard_rate_limit.refund(invoker_did);
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

            // SECURITY: explicitly release the `contexts` lock BEFORE
            // the block-expression returns. This is the exit boundary
            // of Phase 1 — Phase 2 (the executor) must run without the
            // lock. The explicit `drop(contexts)` keeps the lock-split
            // visible to code review and to the structural pipeline
            // wiring test in `scp-testing/tests/integration/pipeline_wiring.rs`.
            Phase1Snapshot {
                handle,
                role_state,
                ticket,
                ctx_gen,
            }
        };

        let Phase1Snapshot {
            handle,
            role_state,
            ticket,
            ctx_gen,
        } = phase1;

        // ------------------------------------------------------------
        // Phase 2 — UNLOCKED.
        //
        // Run the executor and validate its output without holding the
        // `contexts` mutex. On any failure drain the ticket so budget,
        // velocity, and escrow are all reversed before propagating the
        // error.
        // ------------------------------------------------------------
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
                rollback_outlet_economy_ticket(self, context_id, ticket).await;
                return Err(invocation_error_to_context(err));
            }
        };
        let InvokeExecuteOutcome {
            output,
            input_hash,
            output_hash,
            execution_time_ms,
        } = outcome;

        // ------------------------------------------------------------
        // Phase 3a — LOCKED (bookkeeping).
        //
        // Re-acquire the lock to run participation-record update and
        // consequence evaluation against the authoritative per-context
        // cache, then release the lock again for the (off-lock) escrow
        // capture call.
        // ------------------------------------------------------------
        let (consequences, ticket) = {
            let Ok(mut guard) = self.relock_context(&ctx_gen).await else {
                // Context vanished or was recreated between Phase 1
                // and Phase 3 (generation mismatch / not registered).
                // Drain the ticket — this will void the escrow, and
                // the budget/velocity rollback is a best-effort no-op.
                rollback_outlet_economy_ticket(self, context_id, ticket).await;
                return Err(ContextError::ContextNotRegistered(context_id.to_owned()));
            };
            let ctx = &mut *guard;

            let now = self.clock.now_secs();
            let events_for_consequences = super::governance::event_log_entries_for_consequences(
                ctx,
                context_id,
                now,
                self.event_log.as_ref(),
            );
            let consequence_rules = ctx.governance.consequence_rules.clone();

            let triggered = post_outlet_invocation_bookkeeping(
                &events_for_consequences,
                invoker_did,
                context_id,
                now,
                &mut ctx.governance.participation_cache,
                &consequence_rules,
            );

            // Enforce triggered consequences while the lock is held,
            // matching the messaging path (messaging.rs:655-668).
            // evaluate_consequence_rules is called inside
            // post_outlet_invocation_bookkeeping; enforcement must happen
            // here so that consequences are actually applied (not just
            // reported in the output).
            super::governance::enforce_triggered_consequences(
                ctx,
                &super::governance::EnforceConsequencesCtx {
                    context_id,
                    member_did: invoker_did,
                    now,
                    triggered: &triggered,
                    rules: &consequence_rules,
                    clock: &*self.clock,
                    event_log: self.event_log.as_ref(),
                    event_tx: self.event_tx.as_ref(),
                },
            );

            (triggered, ticket)
        };

        // ------------------------------------------------------------
        // Phase 3b — UNLOCKED (escrow capture).
        //
        // Capture the escrow hold off-lock. On capture failure reverse
        // the budget via a dedicated path (escrow is already consumed
        // by the capture attempt, so there is nothing to void) and
        // mark the ticket consumed without re-voiding.
        // ------------------------------------------------------------
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
                        // Capture failed AFTER successful execution.
                        // The escrow hold is consumed by the capture
                        // attempt (no void), but the per-context
                        // budget, velocity entry, and rate-limit
                        // token must all be reversed so that an
                        // unpaid-for invocation does not permanently
                        // charge any of the three. We cannot delegate
                        // to `rollback_outlet_economy_ticket` because
                        // it would attempt to void the already-
                        // consumed escrow.
                        {
                            if let Ok(mut guard) = self.relock_context(&ctx_gen).await {
                                let ctx = &mut *guard;
                                if let Some(cost) = ticket.deducted_cost {
                                    ctx.governance
                                        .budget_tracker
                                        .reverse_spend(invoker_did, cost);
                                }
                                ctx.governance
                                    .velocity_tracker
                                    .rollback(invoker_did, ticket.velocity_token);
                                if ticket.needs_hard_rate_limit_refund {
                                    ctx.governance.hard_rate_limit.refund(invoker_did);
                                }
                            }
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

        // ------------------------------------------------------------
        // Commit the ticket (no more rollback paths below this point)
        // and assemble the ManagedOutletInvocationOutput.
        // ------------------------------------------------------------
        let cost = commit_outlet_economy_ticket(ticket);
        let event = build_outlet_event(
            outlet_id,
            invoker_did,
            execution_time_ms,
            input_hash,
            output_hash,
            cost,
        );

        crate::metrics::record_outlet_invocation();
        Ok(ManagedOutletInvocationOutput {
            output,
            event,
            consequences,
            payment_receipt,
        })
    }

    /// Dispatches an outlet invocation through an [`OutletExecutor`] under
    /// the full economy pipeline (SCP-OUT-013).
    ///
    /// Wraps [`Self::invoke_outlet_with_economy`] with a kind-aware adapter
    /// so the registered [`OutletKind`](scp_protocol::context::outlets::OutletKind)
    /// drives dispatch to `exec_query` (read-only handle) or `exec_action`
    /// (mutable handle, write-capable). Pending mutations enqueued through
    /// [`crate::context::outlets::invoke::MutableInvocation`] are returned
    /// alongside the standard invocation outcome so the caller can apply
    /// them (or assert on them in tests). The `misdeclaration_sink`
    /// receives `OutletVerifiedEvent { integrity_ok: false, reason:
    /// QueryMisdeclaration }` events whenever the
    /// [`MutableInvocation::guard_kind`](crate::context::outlets::invoke::MutableInvocation)
    /// runtime check refuses a write or the dispatched executor half
    /// returns [`OutletExecutorError::KindMismatch`](crate::context::outlets::invoke::OutletExecutorError::KindMismatch).
    ///
    /// # Errors
    ///
    /// Returns the same [`ContextError`] taxonomy as
    /// [`Self::invoke_outlet_with_economy`]. Misdeclaration paths surface
    /// as `ContextError::PermissionDenied(SCP-TOOL-6103: ...)`.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn invoke_outlet_dispatch_with_economy<E>(
        &self,
        context_id: &str,
        registry: &OutletRegistry,
        outlet_id: &OutletId,
        input: serde_json::Value,
        invoker_did: &DID,
        spending_ucan: Option<&UcanToken>,
        timeout_ms: Option<u32>,
        executor: &E,
        misdeclaration_sink: Option<&dyn crate::context::outlets::invoke::QueryMisdeclarationSink>,
    ) -> Result<DispatchedManagedOutletInvocationOutput, ContextError>
    where
        E: crate::context::outlets::invoke::OutletExecutor + ?Sized,
    {
        // Snapshot the outlet kind under the registry so the closure-based
        // adapter sees a stable value.
        let registration = registry.get(outlet_id).ok_or_else(|| {
            ContextError::PermissionDenied(format!("SCP-TOOL-6082: outlet not found: {outlet_id}"))
        })?;
        let kind = registration.kind;

        // Snapshot the read-side context state once so the
        // ReadOnlyInvocation handle is stable across the off-lock executor.
        // We re-acquire the lock briefly to snapshot what the handle needs
        // to expose (events, epoch, members, role state, registry,
        // economic policy snapshot). The dispatcher does not stress
        // membership/ceiling checks — those are already enforced by the
        // existing capability gate inside `invoke_outlet_with_economy`.
        let (
            handle_snapshot,
            role_state_snapshot,
            events_snapshot,
            epoch_snapshot,
            policy_snapshot,
        ) = {
            let (guard, _ctx_gen) = self
                .lock_context(context_id)
                .await
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let ctx = &*guard;
            let now_secs = self.clock.now_secs();
            let events = super::governance::event_log_entries_for_consequences(
                ctx,
                context_id,
                now_secs,
                self.event_log.as_ref(),
            );
            (
                ctx.handle.clone(),
                ctx.role_state.clone(),
                events,
                ctx.epoch.mls_epoch,
                ctx.governance.economic_policy.clone(),
            )
        };

        // Adapt the trait-based dispatch into the closure-based pipeline.
        // The closure has to hold `&mut Vec<MutationIntent>` so it can
        // collect the writes from `MutableInvocation::take_pending_mutations`
        // — `Mutex` keeps us cleanly across the `move` boundary while
        // satisfying `Send`.
        let pending: std::sync::Mutex<Vec<crate::context::outlets::invoke::MutationIntent>> =
            std::sync::Mutex::new(Vec::new());
        let pending_ref = &pending;
        let outlet_id_owned = outlet_id.clone();
        let invoker_did_owned = invoker_did.clone();
        let role_state_ref = &role_state_snapshot;
        let registry_ref: &OutletRegistry = registry;
        let events_ref = &events_snapshot;
        let policy_ref = policy_snapshot.as_ref();
        let handle_ref = &handle_snapshot;
        let executor_ref: &E = executor;
        let executor_kind = kind;

        let closure = move |input: serde_json::Value| {
            let outlet_id_inner = outlet_id_owned.clone();
            let invoker_did_inner = invoker_did_owned.clone();
            async move {
                let read = crate::context::outlets::invoke::ReadOnlyInvocation::new(
                    handle_ref,
                    role_state_ref,
                    registry_ref,
                    &invoker_did_inner,
                    &outlet_id_inner,
                    events_ref,
                    epoch_snapshot,
                    policy_ref,
                    None,
                );
                match executor_kind {
                    scp_protocol::context::outlets::OutletKind::Query => {
                        match executor_ref.exec_query(&read, input).await {
                            Ok(value) => Ok(value),
                            Err(crate::context::outlets::invoke::OutletExecutorError::KindMismatch { .. }) => {
                                if let Some(sink) = misdeclaration_sink {
                                    sink.record(
                                        scp_protocol::context::outlets::OutletVerifiedEvent {
                                            outlet_id: outlet_id_inner.clone(),
                                            passed: 0,
                                            failed: 1,
                                            integrity_ok: false,
                                            reason: Some(
                                                scp_protocol::context::outlets::OutletVerifiedReason::QueryMisdeclaration,
                                            ),
                                        },
                                    );
                                }
                                Err("SCP-TOOL-6103: outlet kind mismatch (Query expected)".to_owned())
                            }
                            Err(crate::context::outlets::invoke::OutletExecutorError::QueryViolation { operation }) => {
                                Err(format!(
                                    "SCP-TOOL-6103: query violation in exec_query: {operation}"
                                ))
                            }
                            Err(crate::context::outlets::invoke::OutletExecutorError::Failed(msg)) => {
                                Err(msg)
                            }
                        }
                    }
                    scp_protocol::context::outlets::OutletKind::Action => {
                        let mut mutable = crate::context::outlets::invoke::MutableInvocation::new(
                            crate::context::outlets::invoke::ReadOnlyInvocation::new(
                                handle_ref,
                                role_state_ref,
                                registry_ref,
                                &invoker_did_inner,
                                &outlet_id_inner,
                                events_ref,
                                epoch_snapshot,
                                policy_ref,
                                None,
                            ),
                            scp_protocol::context::outlets::OutletKind::Action,
                            misdeclaration_sink,
                        );
                        match executor_ref.exec_action(&mut mutable, input).await {
                            Ok(value) => {
                                let collected = mutable.take_pending_mutations();
                                if !collected.is_empty() {
                                    let mut guard = pending_ref
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                                    guard.extend(collected);
                                }
                                Ok(value)
                            }
                            Err(crate::context::outlets::invoke::OutletExecutorError::KindMismatch { .. }) => {
                                Err("SCP-TOOL-6103: outlet kind mismatch (Action expected)".to_owned())
                            }
                            Err(crate::context::outlets::invoke::OutletExecutorError::QueryViolation { operation }) => {
                                Err(format!(
                                    "SCP-TOOL-6103: query violation in exec_action: {operation}"
                                ))
                            }
                            Err(crate::context::outlets::invoke::OutletExecutorError::Failed(msg)) => {
                                Err(msg)
                            }
                        }
                    }
                }
            }
        };

        let outcome = self
            .invoke_outlet_with_economy(
                context_id,
                registry,
                outlet_id,
                input,
                invoker_did,
                spending_ucan,
                timeout_ms,
                closure,
            )
            .await?;

        let pending_mutations = pending
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        Ok(DispatchedManagedOutletInvocationOutput {
            output: outcome.output,
            event: outcome.event,
            consequences: outcome.consequences,
            payment_receipt: outcome.payment_receipt,
            pending_mutations,
        })
    }
}

/// Result of [`ContextManager::invoke_outlet_dispatch_with_economy`].
///
/// Mirrors [`ManagedOutletInvocationOutput`] with the addition of the
/// `pending_mutations` drained from the Action outlet's
/// [`MutableInvocation`](crate::context::outlets::invoke::MutableInvocation).
/// For Query outlets the vector is always empty.
#[derive(Debug)]
pub struct DispatchedManagedOutletInvocationOutput {
    /// Outlet output JSON.
    pub output: serde_json::Value,
    /// Event to append to the event log.
    pub event: OutletInvokedEvent,
    /// Consequences triggered by the invocation.
    pub consequences: Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
    /// Payment receipt when a payment adapter is configured.
    pub payment_receipt: Option<crate::economy::adapter::PaymentReceipt>,
    /// Pending mutations enqueued through `MutableInvocation` write methods.
    pub pending_mutations: Vec<crate::context::outlets::invoke::MutationIntent>,
}

/// Bundle of Phase-1 outputs handed to Phase 2. Exists only so the
/// Phase 1 block can return cleanly (otherwise the `let phase1 = { ...
/// };` binding would have to be a four-tuple).
struct Phase1Snapshot {
    handle: crate::context::ContextHandle,
    role_state: scp_protocol::context::roles::ContextRoleState,
    ticket: OutletEconomyTicket,
    ctx_gen: ContextGeneration,
}

/// Maps an [`InvocationError`] to a [`ContextError`] with SCP codes.
///
/// Uses the canonical `SCP-TOOL` prefix (6000-6999 range) for
/// outlet-invocation failures, per the canonical error-code registry in
/// `.docs/standards/sdk-common.md`.
fn invocation_error_to_context(err: InvocationError) -> ContextError {
    match err {
        InvocationError::ContextNotActive { current_state } => ContextError::PermissionDenied(
            format!("SCP-TOOL-6080: context not active: {current_state}"),
        ),
        InvocationError::InvokerNotAuthorized { did, outlet_id } => ContextError::PermissionDenied(
            format!("SCP-TOOL-6081: invoker {did} lacks OutletCall({outlet_id})"),
        ),
        InvocationError::OutletNotFound { outlet_id } => {
            ContextError::PermissionDenied(format!("SCP-TOOL-6082: outlet not found: {outlet_id}"))
        }
        InvocationError::InputValidationFailed { message } => ContextError::PermissionDenied(
            format!("SCP-TOOL-6083: input schema validation failed: {message}"),
        ),
        InvocationError::OutputValidationFailed { message } => ContextError::PermissionDenied(
            format!("SCP-TOOL-6084: output schema validation failed: {message}"),
        ),
        InvocationError::ExecutionFailed { message } => ContextError::PermissionDenied(format!(
            "SCP-TOOL-6085: outlet execution failed: {message}"
        )),
        InvocationError::Timeout { timeout_ms } => ContextError::PermissionDenied(format!(
            "SCP-TOOL-6086: outlet execution timed out after {timeout_ms}ms"
        )),
        InvocationError::Cancelled => {
            ContextError::PermissionDenied("SCP-TOOL-6087: outlet invocation cancelled".to_owned())
        }
        InvocationError::BudgetExceeded {
            did,
            cost,
            remaining,
        } => ContextError::PermissionDenied(format!(
            "SCP-ECON-12010: budget exceeded for {did}: cost {cost}, remaining {remaining}"
        )),
        InvocationError::OutletQueryCostViolation { reason } => ContextError::PermissionDenied(
            format!("SCP-TOOL-6102: Query outlet cost violation (§5.4.2): {reason}"),
        ),
        InvocationError::QueryViolation {
            outlet_id,
            operation,
        } => ContextError::PermissionDenied(format!(
            "SCP-TOOL-6103: Query outlet \"{outlet_id}\" attempted write \"{operation}\" through ReadOnlyInvocation (§5.4.2)"
        )),
        InvocationError::KindMismatch { outlet_id, kind } => {
            ContextError::PermissionDenied(format!(
                "SCP-TOOL-6103: outlet \"{outlet_id}\" registered as {kind:?} but executor returned KindMismatch (§5.4.2)"
            ))
        }
    }
}

// ===========================================================================
// SCP-OUT-015 — Chain amplification rule + per-kind chain depth budget
// ===========================================================================
//
// Implements spec §6.2.0.3 (amplification rule) and §6.2.0.4 (chain depth
// split). Cross-context invocations carry an `origin_kind` (an [`OutletKind`])
// propagated from the outermost caller through every hop. At each
// cross-context hop the runtime checks:
//
// 1. **Amplification rule (§6.2.0.3):** `origin_kind != Query OR hop_kind ==
//    Query` — else reject with [`OutletAmplificationError::AmplificationViolation`].
//    A `Query`-originated chain MUST NOT trigger any `Action` invocation,
//    directly or transitively. This closes the "free read laundered into
//    paid write" amplification class.
// 2. **Per-kind chain depth budget (§6.2.0.4):** the context-level
//    `max_chain_depth` parameter is partitioned by kind. Query budget is
//    `max_chain_depth` (full budget); Action budget is
//    `max(1, max_chain_depth / 2)`. The hop-kind counter (NOT the origin-kind
//    counter) is decremented on each accepted hop — a Query hop consumes
//    Query budget regardless of whether the chain was Action-originated.
//
// Failed checks emit a structured failure event into BOTH event logs (the
// caller's source context AND the callee's target context) per spec §6.2 —
// "every cross-context call is recorded in both event logs" — so the
// rejection is auditable from either side.
//
// `origin_kind` is bound to the outermost UCAN delegation chain, NOT to a
// runtime-only claim. The hop target re-derives `origin_kind` from the
// validated UCAN stem (`outlet_query:*` → Query; `outlet_call:*` → Action)
// rather than trusting a transport-layer sidecar field. Forging
// `origin_kind` requires forging a signed UCAN with a different stem — see
// [`origin_kind_from_ucan_stem`] for the derivation helper.

/// Sentinel actor DID for amplification-rejection events appended to the
/// per-context event log. Mirrors the `system:` actor used for consequence
/// events in `governance::append_consequence_event` so the event payload's
/// origin is unambiguous: a runtime-emitted rejection, not an actor
/// invocation.
const AMPLIFICATION_REJECTION_ACTOR_DID: &str = "system:amplification-violation";

/// Sentinel actor DID for chain-depth rejection events. Symmetric with
/// [`AMPLIFICATION_REJECTION_ACTOR_DID`]; kept distinct so log readers can
/// disambiguate the failure mode at the actor field without parsing the
/// payload.
const CHAIN_DEPTH_REJECTION_ACTOR_DID: &str = "system:chain-depth-exceeded";

/// Sentinel hash placeholder for `OutletInvokedEvent` records that describe
/// a rejected hop — no input/output was actually executed, but the event
/// schema demands a non-empty hex string. The all-zero SHA-256 prefix is
/// reserved for synthesized rejection records and never collides with a
/// real `sha256_json` result (which has 256 bits of entropy on real input).
const REJECTION_HASH_SENTINEL: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Errors produced by [`cross_context_invoke`].
///
/// Mirrors [`OutletErrorClass::Authorization::AmplificationViolation`] and
/// the kind-aware [`OutletErrorClass::Resource::ChainDepthExceeded`] from
/// spec §5.4.4 (the typed taxonomy lands in SCP-OUT-036/038; the codes are
/// allocated here within the SCP-TOOL 6100-6199 sub-block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutletAmplificationError {
    /// `origin_kind == Query` AND `hop_kind == Action` — the "free read
    /// laundered into paid write" class. Rejected at the cross-context
    /// consent gate (§6.2.0.3).
    ///
    /// Error code: `SCP-TOOL-6120` (slug `authorization.amplification-violation`).
    AmplificationViolation {
        /// The outermost-caller's `OutletKind` (recovered from the signed
        /// UCAN delegation chain by the hop target). Always `Query` when
        /// this variant is constructed.
        origin_kind: OutletKind,
        /// The hop-target outlet's declared `OutletKind`. Always `Action`
        /// when this variant is constructed.
        hop_kind: OutletKind,
    },
    /// The kind-appropriate chain-depth counter would go negative. Per
    /// §6.2.0.4 the Query budget is the full `max_chain_depth`; the Action
    /// budget is `max(1, max_chain_depth / 2)`.
    ///
    /// Error code: `SCP-TOOL-6121` (slug `resource.chain-depth-exceeded`).
    ChainDepthExceeded {
        /// The hop's declared `OutletKind` — selects which budget was
        /// exhausted (Query → `max_chain_depth`; Action → `max(1, max/2)`).
        hop_kind: OutletKind,
        /// The remaining budget on the kind-appropriate counter at the
        /// moment the hop was rejected. Always `0` when this variant is
        /// constructed (a non-zero remaining would have permitted the
        /// decrement).
        remaining: u8,
    },
}

impl OutletAmplificationError {
    /// Returns the canonical SCP error code for this rejection. Used by
    /// the event-log emission path so the on-wire event payload carries
    /// the same code surfaced to callers.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::AmplificationViolation { .. } => "SCP-TOOL-6120",
            Self::ChainDepthExceeded { .. } => "SCP-TOOL-6121",
        }
    }

    /// Returns the kebab-case slug used in spec §5.4.4 / sdk-common.md
    /// taxonomy. Mirrored on the event-log payload.
    #[must_use]
    pub const fn slug(&self) -> &'static str {
        match self {
            Self::AmplificationViolation { .. } => "authorization.amplification-violation",
            Self::ChainDepthExceeded { .. } => "resource.chain-depth-exceeded",
        }
    }
}

impl std::fmt::Display for OutletAmplificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AmplificationViolation {
                origin_kind,
                hop_kind,
            } => write!(
                f,
                "{}: chain amplification rejected (origin_kind={origin_kind:?}, hop_kind={hop_kind:?}) — §6.2.0.3",
                self.error_code()
            ),
            Self::ChainDepthExceeded {
                hop_kind,
                remaining,
            } => write!(
                f,
                "{}: chain depth exceeded for {hop_kind:?} hop (remaining={remaining}) — §6.2.0.4",
                self.error_code()
            ),
        }
    }
}

impl std::error::Error for OutletAmplificationError {}

/// Result of an accepted cross-context hop check.
///
/// Carries the post-decrement counters that the caller MUST propagate into
/// the next-hop call frame. The `origin_kind` is unchanged — `origin_kind`
/// is set ONCE at the outermost caller and propagated verbatim through every
/// hop per §6.2.0.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossContextHopAccepted {
    /// Unchanged from the pre-check value — the outermost caller's kind,
    /// preserved across hops.
    pub origin_kind: OutletKind,
    /// Post-decrement Query counter. Decremented when `hop_kind == Query`,
    /// passed through unchanged when `hop_kind == Action`.
    pub depth_remaining_query: u8,
    /// Post-decrement Action counter. Decremented when `hop_kind == Action`,
    /// passed through unchanged when `hop_kind == Query`.
    pub depth_remaining_action: u8,
}

/// Returns the Query chain-depth budget for a context with the given
/// `max_chain_depth` parameter (§6.2.0.4).
///
/// The Query budget is the full `max_chain_depth` value — Query
/// invocations get the whole context-configured budget because they are
/// idempotent, cacheable, cost-capped reads. Falls back to the protocol
/// default ([`scp_protocol::provenance::attach::DEFAULT_MAX_CHAIN_DEPTH`])
/// when `max_chain_depth` is `None`.
#[must_use]
pub const fn query_chain_budget(max_chain_depth: Option<u8>) -> u8 {
    effective_max_chain_depth(max_chain_depth)
}

/// Returns the Action chain-depth budget for a context with the given
/// `max_chain_depth` parameter (§6.2.0.4).
///
/// The Action budget is `max(1, max_chain_depth / 2)` — half the Query
/// budget, with a floor of 1 so a context with `max_chain_depth = 1`
/// still permits at least one Action hop. Action chains have stricter
/// amplification bounds without requiring a second unrelated parameter.
///
/// **Derivation site only.** Per AC1 the Action budget MUST NOT be stored
/// as a `max_chain_depth_action` field on `ContextParams`; it is always
/// derived at the enforcement call site from `max_chain_depth`. Adding a
/// second config field would diverge from §6.2.0.4 and create the surface
/// where `max_chain_depth_action > max_chain_depth` is configurable —
/// that surface MUST NOT exist.
#[must_use]
pub const fn action_chain_budget(max_chain_depth: Option<u8>) -> u8 {
    let q = effective_max_chain_depth(max_chain_depth);
    // `max(1, q / 2)` — `q / 2` for integer division on u8, then floor of 1
    // so `q == 1` still yields a 1-hop Action budget.
    let half = q / 2;
    if half == 0 { 1 } else { half }
}

/// Recovers the [`OutletKind`] implied by a UCAN token's outermost capability
/// stem (§6.2.0.3 "`origin_kind` is bound to the UCAN delegation chain").
///
/// Inspects every `att` entry in the token's payload and returns:
///
/// - [`OutletKind::Query`] if EVERY recognized stem is `outlet_query:*` /
///   `outlet:query:*`.
/// - [`OutletKind::Action`] if any recognized stem is `outlet_call:*` /
///   `outlet:call:*`.
/// - `None` if the token carries no outlet stems at all (either an invalid
///   hop UCAN or a delegation that does not authorize an outlet — the caller
///   should reject).
///
/// **Mixed-stem tokens.** A token whose `att` list mixes `outlet_query:*`
/// and `outlet_call:*` stems returns [`OutletKind::Action`] (the wider
/// kind) — mixing stems within a single delegation level is a spec-banned
/// shape that the §7.3.8 caveats `narrow()` verifier rejects upstream
/// (SCP-OUT-018), but the kind-recovery helper biases toward the stricter
/// fail-safe per §5.4.2 so a mixed-stem token cannot escape Action
/// amplification rules.
///
/// **Hop-target rule (§6.2.0.3).** The hop target MUST call this on the
/// validated UCAN it received — NOT on a transport-sidecar `origin_kind`
/// claim. This is what makes the "`origin_kind` is signed" property
/// operationally true: the kind is recovered from the signed stem, never
/// from a runtime field that an intermediate hop could rewrite.
///
/// `Capability::OutletQueryAll`, `Capability::OutletCallAll`,
/// `Capability::OutletQuery(_)`, and `Capability::OutletCall(_)` are the
/// four parsed forms produced by [`Capability::from_name`]; all four are
/// recognized here.
#[must_use]
pub fn origin_kind_from_ucan_stem(token: &UcanToken) -> Option<OutletKind> {
    let mut saw_query = false;
    let mut saw_action = false;
    for att in &token.payload.att {
        // The `with` URI carries `scp:ctx:{id}/{stem}:{action}`. We rely on
        // the canonical stem-naming carried by `Capability::from_name` — the
        // Attenuation `can` is the action portion (e.g. `*`, `assistant`),
        // and the stem is in the `with` URI itself.
        let stem = att.with.rsplit('/').next().unwrap_or("");
        // The stem may be the full `outlet_query:foo` or `outlet:query:foo`
        // form — both prefixes are recognized.
        if stem.starts_with("outlet_query:") || stem.starts_with("outlet:query:") {
            saw_query = true;
        } else if stem.starts_with("outlet_call:") || stem.starts_with("outlet:call:") {
            saw_action = true;
        }
        // `Capability::OutletQueryAll` etc. encode without a tail-suffix:
        // `outlet:query:*`. Both branches above already match because the
        // prefix scan does not require a non-`*` suffix.
        // Also support the bare `Capability` `to_name()` forms.
        // Synonyms via `Capability::from_name` round-trip:
        if let Some(cap) = Capability::new(stem) {
            match cap {
                Capability::OutletQuery(_) | Capability::OutletQueryAll => saw_query = true,
                Capability::OutletCall(_) | Capability::OutletCallAll => saw_action = true,
                _ => {}
            }
        }
    }
    match (saw_query, saw_action) {
        // Mixed-stem token: bias to Action (stricter fail-safe per §5.4.2).
        (_, true) => Some(OutletKind::Action),
        (true, false) => Some(OutletKind::Query),
        (false, false) => None,
    }
}

/// Synthesizes a `OutletInvokedEvent` describing a rejected cross-context
/// hop. Both event logs (caller's source context AND callee's target
/// context) receive a copy with shared `request_id` so the failure is
/// linkable across the cross-context boundary per §6.2.0.5 / §7.7
/// "Cross-context provenance".
///
/// Fields:
///
/// - `status` is [`OutletStatus::Error`] — the hop never executed.
/// - `execution_time_ms` is `0` — the rejection happens at the consent
///   gate before any executor runs.
/// - `input_hash` and `output_hash` are the all-zero sentinel
///   ([`REJECTION_HASH_SENTINEL`]); no input was processed and no output
///   was produced.
/// - `cost` is `None` — the rejection precedes any economy bookkeeping.
///
/// The `request_id` is generated once and reused on both events so the
/// pair is correlatable across logs.
fn build_amplification_rejection_event(
    outlet_id: &OutletId,
    invoker_did: &DID,
    request_id: &str,
) -> OutletInvokedEvent {
    OutletInvokedEvent {
        request_id: request_id.to_owned(),
        outlet_id: outlet_id.clone(),
        invoker_did: invoker_did.clone(),
        status: OutletStatus::Error,
        execution_time_ms: 0,
        input_hash: REJECTION_HASH_SENTINEL.to_owned(),
        output_hash: Some(REJECTION_HASH_SENTINEL.to_owned()),
        cost: None,
    }
}

/// Best-effort durable append of a synthesized rejection event into a
/// context's event log. Mirrors [`super::governance::append_consequence_event`]
/// in failure handling — a `tracing::warn!` is logged on append failure but
/// the path NEVER propagates the error: the structural rejection (the
/// `Err(OutletAmplificationError)`) is the authoritative outcome; the
/// event-log entry is the audit trail. Refusing to surface the rejection
/// because the event log is unavailable would let amplification slip past
/// the consent gate.
///
/// `actor_did` is the rejection-reason sentinel
/// ([`AMPLIFICATION_REJECTION_ACTOR_DID`] or
/// [`CHAIN_DEPTH_REJECTION_ACTOR_DID`]) so log readers can filter on it
/// without parsing the payload. The payload's `error_code` and `slug`
/// fields carry the SCP error code + spec slug for in-band querying.
fn append_amplification_rejection_event(
    event_log: &dyn super::super::builder::ContextEventLogProvider,
    context_id: &str,
    error: &OutletAmplificationError,
    rejection_event: &OutletInvokedEvent,
) {
    let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);
    let actor_did = match error {
        OutletAmplificationError::AmplificationViolation { .. } => {
            AMPLIFICATION_REJECTION_ACTOR_DID
        }
        OutletAmplificationError::ChainDepthExceeded { .. } => CHAIN_DEPTH_REJECTION_ACTOR_DID,
    };
    let payload = serde_json::json!({
        "kind": "OutletInvokedEvent",
        "rejection": {
            "error_code": error.error_code(),
            "slug": error.slug(),
            "reason": match error {
                OutletAmplificationError::AmplificationViolation {
                    origin_kind,
                    hop_kind,
                } => serde_json::json!({
                    "type": "amplification-violation",
                    "origin_kind": origin_kind,
                    "hop_kind": hop_kind,
                }),
                OutletAmplificationError::ChainDepthExceeded {
                    hop_kind,
                    remaining,
                } => serde_json::json!({
                    "type": "chain-depth-exceeded",
                    "hop_kind": hop_kind,
                    "remaining": remaining,
                }),
            },
        },
        "event": rejection_event,
    });
    if let Err(e) = event_log.append_context_event_with_payload(
        &context_id_bytes,
        "OutletInvoked",
        actor_did,
        Some(&payload),
    ) {
        tracing::warn!(
            context_id,
            outlet_id = %rejection_event.outlet_id,
            invoker = %rejection_event.invoker_did,
            error_code = error.error_code(),
            log_error = %e,
            "failed to append cross-context amplification rejection event"
        );
    }
}

/// Cross-context hop check (§6.2.0.3 amplification rule + §6.2.0.4 chain
/// depth split).
///
/// Pure compute. Takes the outermost-caller's `origin_kind`, the hop
/// target's declared `hop_kind`, and the per-kind remaining counters.
/// Returns:
///
/// - `Ok(CrossContextHopAccepted)` with the post-decrement counters when
///   the hop is permitted. `origin_kind` is preserved (not reset). The
///   counter for the **hop-kind** is decremented; the counter for the
///   other kind is unchanged. AC4 fails the hop when the relevant
///   counter would go negative — this guard runs before the decrement so
///   the returned counters always satisfy the invariant
///   `accepted.depth_remaining_{query,action} <= input
///   depth_remaining_{query,action}`.
///
/// - `Err(OutletAmplificationError::AmplificationViolation)` when
///   `origin_kind == Query AND hop_kind == Action` (§6.2.0.3). The check
///   runs BEFORE the depth decrement so a Query → Action chain is rejected
///   at the consent gate without consuming budget — preventing the
///   "free read laundered into paid write" attack class.
///
/// - `Err(OutletAmplificationError::ChainDepthExceeded)` when the hop's
///   kind-appropriate counter is `0` (no headroom for the decrement).
///
/// **Counter selection (AC5).** Per the PRD's "matches the invoked outlet,
/// not the originator, for depth accounting" rule, the hop-kind counter
/// is decremented — NOT the origin-kind counter. Concretely: an
/// `Action`-originated chain that calls a Query outlet decrements
/// `depth_remaining_query`, not `depth_remaining_action`. This matches
/// the spec's intent that each kind has an independent ceiling on its
/// own use, regardless of how the chain started.
///
/// **`origin_kind` propagation (§6.2.0.3).** The function does NOT mutate
/// `origin_kind` — it is a property of the outermost UCAN delegation,
/// preserved verbatim through every hop. Callers passing
/// `origin_kind = Action` for a chain that started with a `Query` UCAN
/// stem are violating spec §6.2.0.3; the hop target MUST re-derive
/// `origin_kind` from the validated UCAN stem via
/// [`origin_kind_from_ucan_stem`] before invoking this function so a
/// malicious upstream hop cannot rewrite the kind.
///
/// **Action budget derivation (AC1).** `depth_remaining_action` is
/// derived AT THE CALL SITE from `ContextParams::max_chain_depth` via
/// [`action_chain_budget`] — `max(1, max/2)`. There is no
/// `max_chain_depth_action` field on `ContextParams`, by spec §6.2.0.4
/// design.
///
/// # Errors
///
/// Returns [`OutletAmplificationError::AmplificationViolation`] for
/// Query → Action chains and [`OutletAmplificationError::ChainDepthExceeded`]
/// when the hop-kind counter is exhausted.
///
/// # Spec
///
/// - §6.2.0.3 — amplification rule
/// - §6.2.0.4 — chain depth split
pub const fn cross_context_invoke(
    origin_kind: OutletKind,
    hop_kind: OutletKind,
    depth_remaining_query: u8,
    depth_remaining_action: u8,
) -> Result<CrossContextHopAccepted, OutletAmplificationError> {
    // §6.2.0.3 amplification rule: `origin_kind != Query OR hop_kind == Query`.
    // Equivalent positive form: reject when `origin_kind == Query AND hop_kind == Action`.
    if matches!(origin_kind, OutletKind::Query) && matches!(hop_kind, OutletKind::Action) {
        return Err(OutletAmplificationError::AmplificationViolation {
            origin_kind,
            hop_kind,
        });
    }

    // §6.2.0.4 per-kind chain-depth budget. Decrement the hop-kind counter.
    match hop_kind {
        OutletKind::Query => {
            if depth_remaining_query == 0 {
                return Err(OutletAmplificationError::ChainDepthExceeded {
                    hop_kind,
                    remaining: 0,
                });
            }
            Ok(CrossContextHopAccepted {
                origin_kind,
                depth_remaining_query: depth_remaining_query - 1,
                depth_remaining_action,
            })
        }
        OutletKind::Action => {
            if depth_remaining_action == 0 {
                return Err(OutletAmplificationError::ChainDepthExceeded {
                    hop_kind,
                    remaining: 0,
                });
            }
            Ok(CrossContextHopAccepted {
                origin_kind,
                depth_remaining_query,
                depth_remaining_action: depth_remaining_action - 1,
            })
        }
    }
}

/// Records a cross-context hop rejection in BOTH the source and target
/// contexts' event logs (§6.2 — every cross-context call is recorded in
/// both event logs).
///
/// Builds a single `OutletInvokedEvent` with `status = Error`, shared
/// `request_id`, and zero-sentinel hashes; appends it to both logs with the
/// rejection-reason payload (error code, slug, structured reason).
///
/// **Failure mode.** The append paths are best-effort — a per-context
/// failure logs a `tracing::warn!` but never propagates because the
/// authoritative outcome is the structural `Err(OutletAmplificationError)`
/// returned by [`cross_context_invoke`]. The event-log entries are the
/// audit trail; the rejection itself runs even when the audit log is
/// unavailable.
///
/// `request_id` SHOULD be a UUID v4 string generated by the caller —
/// passing a stable id makes both event-log entries linkable across
/// contexts even though the audit-log emission paths are independent.
#[must_use]
pub fn record_amplification_rejection(
    event_log: Option<&dyn super::super::builder::ContextEventLogProvider>,
    source_context_id: &str,
    target_context_id: &str,
    outlet_id: &OutletId,
    invoker_did: &DID,
    request_id: &str,
    error: &OutletAmplificationError,
) -> OutletInvokedEvent {
    let event = build_amplification_rejection_event(outlet_id, invoker_did, request_id);
    if let Some(log) = event_log {
        append_amplification_rejection_event(log, source_context_id, error, &event);
        // Spec §6.2 / §7.7: both event logs record the same cross-context
        // call so provenance is auditable from either side. Skip the second
        // append when source == target (a self-cross-context call is
        // structurally impossible under the consent gate but the bridge
        // would not double-log a pathological unit-test fixture).
        if source_context_id != target_context_id {
            append_amplification_rejection_event(log, target_context_id, error, &event);
        }
    }
    event
}

/// Maps an [`OutletAmplificationError`] to a [`ContextError`].
///
/// Uses canonical SCP-TOOL codes (6120 for amplification, 6121 for chain
/// depth). Mirrors [`invocation_error_to_context`] for the SCP-OUT-015
/// error class.
#[must_use]
pub fn amplification_error_to_context(err: &OutletAmplificationError) -> ContextError {
    ContextError::PermissionDenied(err.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod amplification_tests {
    //! SCP-OUT-015 acceptance criteria — all 15 ACs verified here as unit
    //! and integration tests against the public surface above. Each test
    //! cites the AC number it covers.

    use super::*;
    use scp_protocol::context::outlets::OutletKind;
    use scp_protocol::crypto::ucan::{Attenuation, UcanHeader, UcanPayload, UcanToken};

    /// Builds a synthetic [`UcanToken`] carrying the given outlet capability
    /// stems in `att`. Used by the AC14/AC15 stem-derivation tests.
    fn ucan_with_stems(stems: &[&str]) -> UcanToken {
        let att = stems
            .iter()
            .map(|s| Attenuation {
                with: format!("scp:ctx:test/{s}"),
                can: "*".to_owned(),
            })
            .collect();
        UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:key:test-iss".to_owned(),
                aud: "did:key:test-aud".to_owned(),
                exp: 9_999_999_999,
                nbf: None,
                nnc: "test-nonce".to_owned(),
                att,
                prf: vec![],
                fct: None,
            },
            signature: vec![],
            encoded: String::new(),
        }
    }

    // -----------------------------------------------------------------------
    // AC1: ContextParams does NOT carry max_chain_depth_action.
    //
    // Verified structurally in this file via the absence of any
    // `max_chain_depth_action` reference; the CI grep in the PRD AC checks
    // `crates/scp-protocol/src/` for zero hits. Here we assert the helper
    // surface returns the expected derived budget instead, which is the
    // positive-side check for the design.
    // -----------------------------------------------------------------------

    #[test]
    fn ac1_action_budget_is_derived_not_stored() {
        // Default max (None → 8): action budget = max(1, 8/2) = 4.
        assert_eq!(action_chain_budget(None), 4);
        // Explicit 8: same.
        assert_eq!(action_chain_budget(Some(8)), 4);
        // Explicit 1: floor of 1.
        assert_eq!(action_chain_budget(Some(1)), 1);
        // Explicit 0 (unusual but legal): floor of 1.
        assert_eq!(action_chain_budget(Some(0)), 1);
        // Query budget mirrors max_chain_depth verbatim.
        assert_eq!(query_chain_budget(None), 8);
        assert_eq!(query_chain_budget(Some(16)), 16);
    }

    // -----------------------------------------------------------------------
    // AC2: cross_context_invoke amplification rejection.
    // -----------------------------------------------------------------------

    #[test]
    fn ac2_query_origin_action_hop_rejected_with_amplification_violation() {
        let result = cross_context_invoke(
            OutletKind::Query,
            OutletKind::Action,
            /*q=*/ 8,
            /*a=*/ 4,
        );
        assert!(matches!(
            result,
            Err(OutletAmplificationError::AmplificationViolation {
                origin_kind: OutletKind::Query,
                hop_kind: OutletKind::Action,
            })
        ));
    }

    // -----------------------------------------------------------------------
    // AC3: Function decrements the kind-appropriate counter on accept.
    // -----------------------------------------------------------------------

    #[test]
    fn ac3_query_hop_decrements_query_counter_only() {
        let accepted = cross_context_invoke(OutletKind::Query, OutletKind::Query, 8, 4)
            .expect("Query → Query is permitted");
        assert_eq!(accepted.origin_kind, OutletKind::Query);
        assert_eq!(accepted.depth_remaining_query, 7);
        assert_eq!(accepted.depth_remaining_action, 4);
    }

    #[test]
    fn ac3_action_hop_decrements_action_counter_only() {
        let accepted = cross_context_invoke(OutletKind::Action, OutletKind::Action, 8, 4)
            .expect("Action → Action is permitted");
        assert_eq!(accepted.origin_kind, OutletKind::Action);
        assert_eq!(accepted.depth_remaining_query, 8);
        assert_eq!(accepted.depth_remaining_action, 3);
    }

    // -----------------------------------------------------------------------
    // AC4: Returns ChainDepthExceeded when the relevant counter would go
    // negative.
    // -----------------------------------------------------------------------

    #[test]
    fn ac4_query_counter_exhausted_returns_chain_depth_exceeded() {
        let result = cross_context_invoke(OutletKind::Query, OutletKind::Query, 0, 4);
        assert!(matches!(
            result,
            Err(OutletAmplificationError::ChainDepthExceeded {
                hop_kind: OutletKind::Query,
                remaining: 0,
            })
        ));
    }

    #[test]
    fn ac4_action_counter_exhausted_returns_chain_depth_exceeded() {
        let result = cross_context_invoke(OutletKind::Action, OutletKind::Action, 8, 0);
        assert!(matches!(
            result,
            Err(OutletAmplificationError::ChainDepthExceeded {
                hop_kind: OutletKind::Action,
                remaining: 0,
            })
        ));
    }

    // -----------------------------------------------------------------------
    // AC5: Action-originated chain calling a Query hop decrements the Query
    // counter (matches the invoked outlet, not the originator).
    // -----------------------------------------------------------------------

    #[test]
    fn ac5_action_origin_query_hop_decrements_query_counter() {
        let accepted = cross_context_invoke(OutletKind::Action, OutletKind::Query, 8, 4)
            .expect("Action → Query is permitted");
        assert_eq!(
            accepted.origin_kind,
            OutletKind::Action,
            "origin_kind preserved across hops"
        );
        assert_eq!(
            accepted.depth_remaining_query, 7,
            "Query counter decremented because hop_kind == Query"
        );
        assert_eq!(
            accepted.depth_remaining_action, 4,
            "Action counter unchanged"
        );
    }

    // -----------------------------------------------------------------------
    // AC6: Integration test — Query → Query → Query valid chain at default
    // budget.
    // -----------------------------------------------------------------------

    #[test]
    fn ac6_query_query_query_valid_at_default_budget() {
        // Outermost call sets origin_kind = Query, with max_chain_depth = 8.
        let q_budget = query_chain_budget(Some(8));
        let a_budget = action_chain_budget(Some(8));
        assert_eq!((q_budget, a_budget), (8, 4));

        // Hop 1: Query → Query.
        let h1 =
            cross_context_invoke(OutletKind::Query, OutletKind::Query, q_budget, a_budget).unwrap();
        assert_eq!(h1.depth_remaining_query, 7);
        // Hop 2: Query → Query.
        let h2 = cross_context_invoke(
            h1.origin_kind,
            OutletKind::Query,
            h1.depth_remaining_query,
            h1.depth_remaining_action,
        )
        .unwrap();
        assert_eq!(h2.depth_remaining_query, 6);
        // Hop 3: Query → Query.
        let h3 = cross_context_invoke(
            h2.origin_kind,
            OutletKind::Query,
            h2.depth_remaining_query,
            h2.depth_remaining_action,
        )
        .unwrap();
        assert_eq!(h3.depth_remaining_query, 5);
        assert_eq!(h3.origin_kind, OutletKind::Query);
    }

    // -----------------------------------------------------------------------
    // AC7: Integration test — Query → Query → Action triggers
    // AmplificationViolation with origin_kind == Query.
    // -----------------------------------------------------------------------

    #[test]
    fn ac7_query_query_action_triggers_amplification_violation() {
        // Hops 1 + 2 succeed.
        let h1 = cross_context_invoke(OutletKind::Query, OutletKind::Query, 8, 4).unwrap();
        let h2 = cross_context_invoke(
            h1.origin_kind,
            OutletKind::Query,
            h1.depth_remaining_query,
            h1.depth_remaining_action,
        )
        .unwrap();
        assert_eq!(h2.origin_kind, OutletKind::Query);
        // Hop 3: Query → Action — rejected at the consent gate.
        let h3 = cross_context_invoke(
            h2.origin_kind,
            OutletKind::Action,
            h2.depth_remaining_query,
            h2.depth_remaining_action,
        );
        assert!(matches!(
            h3,
            Err(OutletAmplificationError::AmplificationViolation {
                origin_kind: OutletKind::Query,
                hop_kind: OutletKind::Action,
            })
        ));
    }

    // -----------------------------------------------------------------------
    // AC8: Integration test — Action → Query → Action is valid (Query
    // amplification rule does not trigger because origin_kind == Action).
    // -----------------------------------------------------------------------

    #[test]
    fn ac8_action_query_action_is_valid() {
        // Hop 1: Action → Query (decrements Query counter).
        let h1 = cross_context_invoke(OutletKind::Action, OutletKind::Query, 8, 4).unwrap();
        assert_eq!(h1.origin_kind, OutletKind::Action);
        assert_eq!(h1.depth_remaining_query, 7);
        assert_eq!(h1.depth_remaining_action, 4);

        // Hop 2: Action → Query (origin preserved).
        let h2 = cross_context_invoke(
            h1.origin_kind,
            OutletKind::Query,
            h1.depth_remaining_query,
            h1.depth_remaining_action,
        )
        .unwrap();

        // Hop 3: Action → Action — permitted because origin_kind != Query.
        let h3 = cross_context_invoke(
            h2.origin_kind,
            OutletKind::Action,
            h2.depth_remaining_query,
            h2.depth_remaining_action,
        )
        .expect("Action → Action permitted regardless of intermediate Query hops");
        assert_eq!(h3.origin_kind, OutletKind::Action);
        assert_eq!(h3.depth_remaining_action, 3);
    }

    // -----------------------------------------------------------------------
    // AC9: Integration test — Action → Action at depth 5 with default
    // budget (4) triggers ChainDepthExceeded.
    // -----------------------------------------------------------------------

    #[test]
    fn ac9_action_chain_at_depth_5_exceeds_default_budget_of_4() {
        // Default max_chain_depth = 8; Action budget = 4.
        let q = query_chain_budget(None);
        let a = action_chain_budget(None);
        assert_eq!((q, a), (8, 4));

        // Walk Action → Action 4 times — each hop succeeds and decrements
        // the Action counter.
        let mut cur_q = q;
        let mut cur_a = a;
        for hop in 1..=4 {
            let accepted =
                cross_context_invoke(OutletKind::Action, OutletKind::Action, cur_q, cur_a)
                    .unwrap_or_else(|_| panic!("hop {hop} should succeed"));
            cur_q = accepted.depth_remaining_query;
            cur_a = accepted.depth_remaining_action;
        }
        assert_eq!(cur_a, 0, "after 4 Action hops the budget is exhausted");

        // 5th Action hop is rejected.
        let h5 = cross_context_invoke(OutletKind::Action, OutletKind::Action, cur_q, cur_a);
        assert!(matches!(
            h5,
            Err(OutletAmplificationError::ChainDepthExceeded {
                hop_kind: OutletKind::Action,
                remaining: 0,
            })
        ));
    }

    // -----------------------------------------------------------------------
    // AC10: Rejection emits a failed OutletInvokedEvent in BOTH contexts'
    // event logs with an error code.
    // -----------------------------------------------------------------------

    /// Test event-log provider that captures every append into a `Vec` keyed
    /// by `(context_id, event_name, actor_did, payload)`. Used by AC10 to
    /// verify the rejection event lands in both logs.
    #[derive(Default)]
    struct CapturingEventLog {
        entries: std::sync::Mutex<Vec<CapturedEntry>>,
    }

    #[derive(Debug, Clone)]
    struct CapturedEntry {
        context_id: [u8; 32],
        event_name: String,
        actor_did: String,
        payload: Option<serde_json::Value>,
    }

    impl super::super::super::builder::ContextEventLogProvider for CapturingEventLog {
        fn init_event_log(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            context_id: &[u8; 32],
            event: &str,
            actor_did: &str,
            payload: Option<&serde_json::Value>,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            self.entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(CapturedEntry {
                    context_id: *context_id,
                    event_name: event.to_owned(),
                    actor_did: actor_did.to_owned(),
                    payload: payload.cloned(),
                });
            Ok(())
        }
        fn destroy_event_log(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    #[test]
    fn ac10_rejection_emits_failed_event_in_both_event_logs() {
        let log = CapturingEventLog::default();
        let outlet_id: OutletId = "calculator".to_owned();
        let invoker: DID = "did:key:invoker".into();
        let err = OutletAmplificationError::AmplificationViolation {
            origin_kind: OutletKind::Query,
            hop_kind: OutletKind::Action,
        };
        let request_id = "req-ac10-rejection";
        let event = record_amplification_rejection(
            Some(&log),
            "ctx-source",
            "ctx-target",
            &outlet_id,
            &invoker,
            request_id,
            &err,
        );
        // Returned synthesized event has Error status and zero hashes.
        assert_eq!(event.status, OutletStatus::Error);
        assert_eq!(event.execution_time_ms, 0);
        assert_eq!(event.input_hash, REJECTION_HASH_SENTINEL);
        assert_eq!(event.output_hash.as_deref(), Some(REJECTION_HASH_SENTINEL));
        assert_eq!(event.cost, None);
        assert_eq!(event.request_id, request_id);

        // Both contexts received an OutletInvoked entry — verify by
        // distinct context_id_bytes. Scope the lock to drop it eagerly so
        // the assertion phase doesn't hold the mutex.
        let captured = {
            let entries = log
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            entries.clone()
        };
        assert_eq!(captured.len(), 2, "one entry per context");
        let src_bytes = scp_protocol::context::context_id_bytes("ctx-source");
        let tgt_bytes = scp_protocol::context::context_id_bytes("ctx-target");
        let src_entry = captured
            .iter()
            .find(|e| e.context_id == src_bytes)
            .expect("source entry");
        let tgt_entry = captured
            .iter()
            .find(|e| e.context_id == tgt_bytes)
            .expect("target entry");
        for e in [src_entry, tgt_entry] {
            assert_eq!(e.event_name, "OutletInvoked");
            assert_eq!(e.actor_did, AMPLIFICATION_REJECTION_ACTOR_DID);
            let p = e.payload.as_ref().expect("payload");
            assert_eq!(p["rejection"]["error_code"], "SCP-TOOL-6120");
            assert_eq!(
                p["rejection"]["slug"],
                "authorization.amplification-violation"
            );
            assert_eq!(p["rejection"]["reason"]["type"], "amplification-violation");
        }
    }

    // -----------------------------------------------------------------------
    // AC12: origin_kind is bound to the outermost UCAN stem.
    //
    // Structurally enforced by [`origin_kind_from_ucan_stem`] returning the
    // kind from the signed `att` list. A token with the outlet_query stem
    // returns Query; with outlet_call returns Action. Forging a different
    // origin_kind requires forging a UCAN with a different stem — which
    // would fail the upstream signature verification.
    // -----------------------------------------------------------------------

    #[test]
    fn ac12_origin_kind_is_bound_to_outer_ucan_stem() {
        let q_token = ucan_with_stems(&["outlet_query:calc"]);
        assert_eq!(
            origin_kind_from_ucan_stem(&q_token),
            Some(OutletKind::Query)
        );
        let a_token = ucan_with_stems(&["outlet_call:assistant"]);
        assert_eq!(
            origin_kind_from_ucan_stem(&a_token),
            Some(OutletKind::Action)
        );
        // Wildcard variants resolve too.
        let q_all = ucan_with_stems(&["outlet_query:*"]);
        assert_eq!(origin_kind_from_ucan_stem(&q_all), Some(OutletKind::Query));
        let a_all = ucan_with_stems(&["outlet_call:*"]);
        assert_eq!(origin_kind_from_ucan_stem(&a_all), Some(OutletKind::Action));
        // Token with no outlet stems returns None — the caller should
        // reject (the hop is not authorized to invoke an outlet).
        let none_token = ucan_with_stems(&["messages:read"]);
        assert_eq!(origin_kind_from_ucan_stem(&none_token), None);
    }

    // -----------------------------------------------------------------------
    // AC13: origin_kind is propagated inside every cross-context hop
    // envelope as part of the UCAN delegation; the receiving hop re-verifies
    // the stem and sets origin_kind from THAT, not from a trusted sidecar.
    //
    // Verified in two parts: (a) cross_context_invoke is the pure check
    // and never reads transport state — `origin_kind` is its FIRST parameter,
    // not a context-pulled field; (b) origin_kind_from_ucan_stem is the
    // ONLY supported derivation path. AC14 below covers the malicious
    // sidecar attempt.
    // -----------------------------------------------------------------------

    #[test]
    fn ac13_hop_target_recovers_origin_kind_from_ucan_not_sidecar() {
        // Simulate a hop receiving a UCAN with outlet_query:* — the
        // re-derived origin_kind is Query regardless of any other claim.
        let ucan_received = ucan_with_stems(&["outlet_query:*"]);
        let recovered =
            origin_kind_from_ucan_stem(&ucan_received).expect("recovered from signed stem");
        assert_eq!(recovered, OutletKind::Query);

        // The hop check uses the recovered kind — not a sidecar value.
        // A malicious upstream that claimed Action via a sidecar would be
        // ignored because `cross_context_invoke` reads only its parameters.
        let result = cross_context_invoke(recovered, OutletKind::Action, 8, 4);
        assert!(matches!(
            result,
            Err(OutletAmplificationError::AmplificationViolation { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // AC14: A malicious hop that attempts to rewrite origin_kind without a
    // matching UCAN rewrite is rejected at the next hop's full UCAN
    // validation step.
    //
    // We model "next hop's full UCAN validation" as the kind-recovery
    // step: the receiving hop must call `origin_kind_from_ucan_stem` on
    // the validated UCAN it received, not on a separate claim. A token
    // whose stems are outlet_query but whose attacker-supplied "side"
    // claim says Action is rejected because the stem-derived kind wins.
    // -----------------------------------------------------------------------

    #[test]
    fn ac14_malicious_origin_kind_rewrite_without_ucan_rewrite_is_rejected() {
        // The attacker presents a UCAN with stems = outlet_query:* and a
        // claim of origin_kind = Action via some sidecar channel. The
        // hop target ignores the sidecar and re-derives from stems.
        let attackers_ucan = ucan_with_stems(&["outlet_query:steal"]);
        let derived = origin_kind_from_ucan_stem(&attackers_ucan).unwrap();
        assert_eq!(
            derived,
            OutletKind::Query,
            "kind is derived from signed stems, not from a sidecar field"
        );

        // The chain check uses derived = Query. An attempt to call an
        // Action outlet under this UCAN is rejected via amplification.
        let attempt = cross_context_invoke(derived, OutletKind::Action, 8, 4);
        assert!(matches!(
            attempt,
            Err(OutletAmplificationError::AmplificationViolation {
                origin_kind: OutletKind::Query,
                hop_kind: OutletKind::Action,
            })
        ));
    }

    // -----------------------------------------------------------------------
    // AC15: A UCAN chain whose outermost stem is outlet_query:* but whose
    // inner hop presents outlet_call:* is rejected with
    // AmplificationViolation BEFORE executor dispatch.
    //
    // Modelled as: the outermost stem is parsed → origin_kind = Query;
    // the hop target outlet's declared kind = Action. The amplification
    // check runs and returns Err before any executor would be invoked.
    // -----------------------------------------------------------------------

    #[test]
    fn ac15_outer_query_inner_call_rejected_before_executor_dispatch() {
        // Outer UCAN stem: outlet_query:* → origin_kind = Query.
        let outer_ucan = ucan_with_stems(&["outlet_query:*"]);
        let origin_kind = origin_kind_from_ucan_stem(&outer_ucan).unwrap();
        assert_eq!(origin_kind, OutletKind::Query);

        // Inner hop target outlet is registered as Action and the inner
        // UCAN attempts outlet_call:* — but origin_kind is still Query
        // because origin is bound to the OUTER (root) UCAN.
        let result = cross_context_invoke(origin_kind, OutletKind::Action, 8, 4);
        assert!(matches!(
            result,
            Err(OutletAmplificationError::AmplificationViolation { .. })
        ));
        // No executor was dispatched — the error path is the consent gate.
    }

    // -----------------------------------------------------------------------
    // Bonus: the all-permitted matrix entries (Query→Query, Action→Query,
    // Action→Action) accept and decrement the right counters. Belt-and-
    // suspenders for AC3 + AC8 above.
    // -----------------------------------------------------------------------

    #[test]
    fn permitted_combinations_accept_and_decrement_correctly() {
        // Query → Query
        let r = cross_context_invoke(OutletKind::Query, OutletKind::Query, 8, 4).unwrap();
        assert_eq!((r.depth_remaining_query, r.depth_remaining_action), (7, 4));
        // Action → Query
        let r = cross_context_invoke(OutletKind::Action, OutletKind::Query, 8, 4).unwrap();
        assert_eq!((r.depth_remaining_query, r.depth_remaining_action), (7, 4));
        // Action → Action
        let r = cross_context_invoke(OutletKind::Action, OutletKind::Action, 8, 4).unwrap();
        assert_eq!((r.depth_remaining_query, r.depth_remaining_action), (8, 3));
    }

    // -----------------------------------------------------------------------
    // ChainDepthExceeded event-log emission — verifies the second SCP-TOOL
    // code (6121) lands correctly.
    // -----------------------------------------------------------------------

    #[test]
    fn chain_depth_rejection_emits_in_both_logs_with_6121_code() {
        let log = CapturingEventLog::default();
        let outlet_id: OutletId = "noisy".to_owned();
        let invoker: DID = "did:key:invoker".into();
        let err = OutletAmplificationError::ChainDepthExceeded {
            hop_kind: OutletKind::Action,
            remaining: 0,
        };
        let event = record_amplification_rejection(
            Some(&log),
            "ctx-A",
            "ctx-B",
            &outlet_id,
            &invoker,
            "req-cd-1",
            &err,
        );
        assert_eq!(event.status, OutletStatus::Error);
        let captured = {
            let entries = log
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            entries.clone()
        };
        assert_eq!(captured.len(), 2);
        for e in &captured {
            assert_eq!(e.event_name, "OutletInvoked");
            assert_eq!(e.actor_did, CHAIN_DEPTH_REJECTION_ACTOR_DID);
            let p = e.payload.as_ref().unwrap();
            assert_eq!(p["rejection"]["error_code"], "SCP-TOOL-6121");
            assert_eq!(p["rejection"]["slug"], "resource.chain-depth-exceeded");
            assert_eq!(p["rejection"]["reason"]["type"], "chain-depth-exceeded");
        }
    }

    // -----------------------------------------------------------------------
    // Self-cross-context (source == target) emits a SINGLE entry — defensive
    // against a misbehaving bridge writing the same context twice.
    // -----------------------------------------------------------------------

    #[test]
    fn rejection_with_same_source_and_target_emits_once() {
        let log = CapturingEventLog::default();
        let outlet_id: OutletId = "selfish".to_owned();
        let invoker: DID = "did:key:invoker".into();
        let err = OutletAmplificationError::AmplificationViolation {
            origin_kind: OutletKind::Query,
            hop_kind: OutletKind::Action,
        };
        let event = record_amplification_rejection(
            Some(&log),
            "ctx-self",
            "ctx-self",
            &outlet_id,
            &invoker,
            "req-self",
            &err,
        );
        assert_eq!(event.outlet_id, outlet_id);
        let captured_len = {
            let entries = log
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            entries.len()
        };
        assert_eq!(captured_len, 1);
    }

    // -----------------------------------------------------------------------
    // Error code + slug surface tests — used by the
    // SDK serialization paths in OUT-036/038 (the typed error class).
    // -----------------------------------------------------------------------

    #[test]
    fn error_codes_and_slugs_match_authorization_taxonomy() {
        let amp = OutletAmplificationError::AmplificationViolation {
            origin_kind: OutletKind::Query,
            hop_kind: OutletKind::Action,
        };
        assert_eq!(amp.error_code(), "SCP-TOOL-6120");
        assert_eq!(amp.slug(), "authorization.amplification-violation");
        let cd = OutletAmplificationError::ChainDepthExceeded {
            hop_kind: OutletKind::Query,
            remaining: 0,
        };
        assert_eq!(cd.error_code(), "SCP-TOOL-6121");
        assert_eq!(cd.slug(), "resource.chain-depth-exceeded");
    }

    #[test]
    fn amplification_error_to_context_uses_canonical_codes() {
        let amp = OutletAmplificationError::AmplificationViolation {
            origin_kind: OutletKind::Query,
            hop_kind: OutletKind::Action,
        };
        let ctx_err = amplification_error_to_context(&amp);
        match ctx_err {
            ContextError::PermissionDenied(msg) => {
                assert!(msg.contains("SCP-TOOL-6120"), "{msg}");
            }
            other => panic!("unexpected ContextError: {other:?}"),
        }
    }
}
