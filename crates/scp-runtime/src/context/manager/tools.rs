//! `ContextManager::invoke_tool_with_economy` — tool invocation with
//! per-DID anti-spam escalation wired from per-context governance state.
//!
//! This wrapper is the integration point between the free
//! [`invoke_tool_execute_and_validate`](crate::context::tools::invoke::invoke_tool_execute_and_validate)
//! helper and the [`super::ContextManager`] per-context state. It
//! snapshots economic policy, budget tracker, per-DID velocity tracker,
//! message pricing config, a real event-log snapshot, consequence rules,
//! metrics, and participation cache from the context's `GovernanceState`
//! so that tool invocations participate in the same per-DID anti-spam
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
//!    [`ToolEconomyTicket`] is assembled from the resulting bookkeeping.
//! 2. **Phase 2 — unlocked:** the `contexts` lock is dropped; the executor
//!    is dispatched via
//!    [`invoke_tool_execute_and_validate`](crate::context::tools::invoke::invoke_tool_execute_and_validate)
//!    which performs context-state, capability, schema, timeout, and
//!    output-schema checks *again* (defensive) using the snapshotted
//!    handle + role state. On any error the ticket is drained
//!    (budget reversed, velocity entry rolled back, escrow voided).
//! 3. **Phase 3 — locked then unlocked:** the lock is re-acquired to run
//!    post-invocation bookkeeping (participation cache, consequence
//!    evaluation), then released again for the escrow-capture call.
//!    Only then is the ticket committed.
//!
//! The `ToolEconomyTicket` is `#[must_use]` with a `Drop` guard that
//! debug-asserts in tests so no future refactor can leak an unbalanced
//! budget deduction or velocity entry on an untested error branch.
//!
//! # Registry ownership
//!
//! The wrapper takes the [`ToolRegistry`] and executor as explicit
//! parameters because the manager does not own a per-context tool
//! registry today (it lives in the FFI bridge layers). This preserves
//! the bridge-owned registry invariant while keeping tool invocations
//! within the full governance pipeline.

use std::collections::HashMap;
use std::future::Future;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::tools::ToolId;
use scp_protocol::context::tools::lifecycle::ToolInvokedEvent;
use scp_protocol::context::tools::registry::ToolRegistry;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::economy::antispam::VelocityRollbackToken;
use scp_protocol::economy::policy::ObservableMetrics;
use scp_protocol::economy::types::Amount;

use crate::context::tools::invoke::{
    self, InvocationError, InvokeExecuteOutcome, ToolEconomyContext, build_tool_event,
    economy_pre_check, invoke_tool_execute_and_validate, post_tool_invocation_bookkeeping,
};
use crate::economy::adapter::PaymentAdapterDyn;
use crate::economy::integration::PreparedAction;

use super::{Arc, ContextManager};

/// Result of a successful managed tool invocation.
#[derive(Debug)]
pub struct ManagedToolInvocationOutput {
    /// Tool output JSON.
    pub output: serde_json::Value,
    /// Event to append to the event log.
    pub event: ToolInvokedEvent,
    /// Consequences triggered by the invocation.
    pub consequences: Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
    /// Payment receipt when a payment adapter is configured.
    pub payment_receipt: Option<crate::economy::adapter::PaymentReceipt>,
}

/// Phase-1 bookkeeping bundle for a tool invocation in flight.
///
/// Every Phase 1 success produces a [`ToolEconomyTicket`]; every Phase 2
/// or Phase 3 error branch MUST drain it through
/// [`rollback_tool_economy_ticket`] (refund budget + roll back velocity
/// entry + void escrow) or commit it through
/// [`commit_tool_economy_ticket`]. Dropping it without doing one or the
/// other is a compile-time warning (`#[must_use]`) and a `Drop`
/// debug-assert so unit tests fail loudly.
///
/// Mirrors [`super::economy::EconomyTicket`] one-for-one; a separate
/// type exists because the tool path also owns a cloned `PreparedAction`
/// escrow handle and the void + capture steps use the tool-flavor
/// adapter helpers in [`crate::context::tools::invoke`].
#[must_use = "ToolEconomyTicket must be committed or rolled back — dropping leaks budget, velocity, and escrow state"]
struct ToolEconomyTicket {
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
    /// [`invoke::complete_tool_payment`] in Phase 3 so the capture step
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

/// Marks the ticket committed (success path). Returns the deducted cost
/// so the caller can populate the `ToolInvokedEvent`. Clears
/// `needs_hard_rate_limit_refund` so the invariant
/// "`needs_hard_rate_limit_refund == true` iff a refund is still owed"
/// holds against any defensive rollback call.
fn commit_tool_economy_ticket(mut ticket: ToolEconomyTicket) -> Option<Amount> {
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
async fn rollback_tool_economy_ticket(
    manager: &ContextManager,
    context_id: &str,
    mut ticket: ToolEconomyTicket,
) {
    ticket.consumed = true;

    // Void the adapter-side escrow first so it does not survive the
    // manager-side rollback. This mirrors `void_escrow_and_rollback` in
    // the free `invoke_tool` path.
    if let (Some(adapter), Some(prepared)) =
        (manager.payment_adapter.as_ref(), ticket.escrow.as_ref())
    {
        invoke::void_tool_escrow(adapter.as_ref(), prepared).await;
    }

    // Reacquire the lock and reverse the per-context bookkeeping.
    if let Some(entry) = manager.contexts.get(context_id) {
        let arc = entry.value().clone();
        drop(entry);
        let mut _guard = arc.lock().await;
        let ctx = &mut *_guard;
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
    /// not flow through [`Self::invoke_tool_with_economy`] (the
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
    /// will fail with a more specific "tool not found" error, and
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
        let Some(entry) = self.contexts.get(context_id) else {
            return true;
        };
        let arc = entry.value().clone();
        drop(entry);
        let ctx = arc.blocking_lock();
        ctx.governance.hard_rate_limit.try_consume(did, now_secs)
    }

    /// Synchronously refund one hard-rate-limit token. No-op if the
    /// context is unknown. Same `blocking_lock` constraint as
    /// [`Self::try_consume_hard_rate_limit_blocking`].
    pub fn refund_hard_rate_limit_blocking(&self, context_id: &str, did: &DID) {
        let Some(entry) = self.contexts.get(context_id) else {
            return;
        };
        let arc = entry.value().clone();
        drop(entry);
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
        let Some(entry) = self.contexts.get(context_id) else {
            return true;
        };
        let arc = entry.value().clone();
        drop(entry);
        let mut _guard = arc.lock().await;
        let ctx = &mut *_guard;
        ctx.governance.hard_rate_limit.try_consume(did, now_secs)
    }

    /// Async refund. No-op if the context is unknown.
    pub async fn refund_hard_rate_limit(&self, context_id: &str, did: &DID) {
        if let Some(_entry) = self.contexts.get(context_id) {
            let _ctx_arc = Arc::clone(_entry.value());
            drop(_entry);
            let _guard = _ctx_arc.lock().await;
            let ctx = &*_guard;
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

    /// Invokes a tool under the full economy pipeline without holding
    /// the `contexts` mutex across the executor future (spec §19.7).
    ///
    /// This is the single entry point that tool-invoking bridges should
    /// use when they want the runtime to enforce per-DID escalation,
    /// floor/cap, and velocity tracking for `ToolInvoke` actions. The
    /// [`ToolRegistry`] and `executor` are passed in because the bridge
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
    ///    [`ToolEconomyTicket`]. The lock is released at the end of
    ///    Phase 1.
    /// 2. **Phase 2 (unlocked):** dispatch the executor via
    ///    [`invoke_tool_execute_and_validate`]. On any failure the
    ///    ticket is drained (budget, velocity, escrow).
    /// 3. **Phase 3 (locked then unlocked):** re-acquire the lock for
    ///    post-invocation bookkeeping (participation cache + consequence
    ///    evaluation), release the lock, capture the escrow off-lock,
    ///    commit the ticket, and build the `ToolInvokedEvent`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if the context is
    /// unknown in Phase 1 or 3. Returns [`ContextError::PermissionDenied`]
    /// (with an `SCP-ECON-*` or `SCP-CTX-*` code) on any invocation,
    /// budget, UCAN composition, schema validation, or consequence
    /// failure. All errors are terminal for the invocation; partial
    /// state mutations (budget, velocity, escrow) are rolled back before
    /// the error is returned via the `ToolEconomyTicket`.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        clippy::significant_drop_tightening
    )]
    pub async fn invoke_tool_with_economy<F, Fut>(
        &self,
        context_id: &str,
        registry: &ToolRegistry,
        tool_id: &ToolId,
        input: serde_json::Value,
        invoker_did: &DID,
        spending_ucan: Option<&UcanToken>,
        timeout_ms: Option<u32>,
        executor: F,
    ) -> Result<ManagedToolInvocationOutput, ContextError>
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
        // [`ToolEconomyTicket`]. Phase 1 ends with `drop(contexts)`
        // so Phase 2 (the executor) runs WITHOUT the lock.
        // ------------------------------------------------------------
        let now_secs = self.clock.now_secs();
        let payment_adapter: Option<Arc<dyn PaymentAdapterDyn>> = self.payment_adapter.clone();

        let phase1 = {
            let _ctx_arc = self
                .get_context_arc(context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let mut _guard = _ctx_arc.lock().await;
            let ctx = &mut *_guard;

            let handle = ctx.handle.clone();
            let role_state = ctx.role_state.clone();

            // Defense-in-depth Matrix-style hard rate limit: consume
            // a token from the per-invoker bucket BEFORE any
            // bookkeeping so the cap applies even when the cost
            // pipeline is free. Inline rollback paths refund
            // directly; the `ToolEconomyTicket`-based rollback
            // consults `needs_hard_rate_limit_refund`.
            if !ctx
                .governance
                .hard_rate_limit
                .try_consume(invoker_did, now_secs)
            {
                return Err(ContextError::RateLimited {
                    resource: "tool_invoke".to_owned(),
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
                let economy = ToolEconomyContext {
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
            // (used by send/join) already runs this pipeline; `invoke_tool_with_economy`
            // must match. For free actions (`action_cost == 0`) spending UCANs
            // are not required — mirroring `enforce_economy` and `check_spending_capability`.
            if action_cost.0 > 0 {
                let Some(spending) = spending_ucan else {
                    // Paid action reached this point without a spending UCAN:
                    // `economy_pre_check` would normally reject this via
                    // `check_tool_spending_capability`, so reaching here is
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

            let snapshot = Phase1Snapshot {
                handle,
                role_state,
                ticket,
            };
            // SECURITY: explicitly release the `contexts` lock BEFORE
            // the block-expression returns. This is the exit boundary
            // of Phase 1 — Phase 2 (the executor) must run without the
            // lock. The explicit `drop(contexts)` keeps the lock-split
            // visible to code review and to the structural pipeline
            // wiring test in `scp-testing/tests/integration/pipeline_wiring.rs`.
            snapshot
        };

        let Phase1Snapshot {
            handle,
            role_state,
            ticket,
        } = phase1;

        // ------------------------------------------------------------
        // Phase 2 — UNLOCKED.
        //
        // Run the executor and validate its output without holding the
        // `contexts` mutex. On any failure drain the ticket so budget,
        // velocity, and escrow are all reversed before propagating the
        // error.
        // ------------------------------------------------------------
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
                rollback_tool_economy_ticket(self, context_id, ticket).await;
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
            let _ctx_arc = if let Some(entry) = self.contexts.get(context_id) {
                entry.value().clone()
            } else {
                // Context vanished between Phase 1 and Phase 3 (e.g.
                // closed concurrently). Drain the ticket — this will
                // void the escrow, and the budget/velocity rollback is
                // a best-effort no-op.
                rollback_tool_economy_ticket(self, context_id, ticket).await;
                return Err(ContextError::ContextNotRegistered(context_id.to_owned()));
            };
            let mut _guard = _ctx_arc.lock().await;
            let ctx = &mut *_guard;

            let now = self.clock.now_secs();
            let events_for_consequences = super::governance::event_log_entries_for_consequences(
                ctx,
                context_id,
                now,
                self.event_log.as_ref(),
            );
            let consequence_rules = ctx.governance.consequence_rules.clone();

            let triggered = post_tool_invocation_bookkeeping(
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
            // post_tool_invocation_bookkeeping; enforcement must happen
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
                        // Capture failed AFTER successful execution.
                        // The escrow hold is consumed by the capture
                        // attempt (no void), but the per-context
                        // budget, velocity entry, and rate-limit
                        // token must all be reversed so that an
                        // unpaid-for invocation does not permanently
                        // charge any of the three. We cannot delegate
                        // to `rollback_tool_economy_ticket` because
                        // it would attempt to void the already-
                        // consumed escrow.
                        {
                            if let Some(_entry) = self.contexts.get(context_id) {
                                let _ctx_arc = Arc::clone(_entry.value());
                                drop(_entry);
                                let mut _guard = _ctx_arc.lock().await;
                                let ctx = &mut *_guard;
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
        // and assemble the ManagedToolInvocationOutput.
        // ------------------------------------------------------------
        let cost = commit_tool_economy_ticket(ticket);
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
}

/// Bundle of Phase-1 outputs handed to Phase 2. Exists only so the
/// Phase 1 block can return cleanly (otherwise the `let phase1 = { ...
/// };` binding would have to be a four-tuple).
struct Phase1Snapshot {
    handle: crate::context::ContextHandle,
    role_state: scp_protocol::context::roles::ContextRoleState,
    ticket: ToolEconomyTicket,
}

/// Maps an [`InvocationError`] to a [`ContextError`] with SCP codes.
///
/// Uses the canonical `SCP-TOOL` prefix (6000-6999 range) for
/// tool-invocation failures, per the canonical error-code registry in
/// `.docs/standards/sdk-common.md`.
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
