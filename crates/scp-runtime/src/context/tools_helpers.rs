// Module-level allow — the legacy inherent-impl form in
// `manager/tools.rs` carried `#[allow(clippy::significant_drop_tightening)]`
// on individual methods (two-step borrow on the contexts map). The hoisted
// bodies preserve the same lock-hold-across-await patterns deliberately
// (narrowing changes lock-ordering semantics); allowing the lint
// crate-locally keeps the hoist byte-identical to the legacy behavior.
#![allow(clippy::significant_drop_tightening)]

//! Tools-domain helpers with explicit-collaborator signatures
//! (ADR-049 §12c.4).
//!
//! # Purpose
//!
//! This module hoists the tools-domain methods that the actor handler in
//! [`crate::context::actor::handlers::tools`] currently reaches via
//! `view.manager().X(...)`. The hoist is a **pre-work** commit for the
//! actor handler body migration (later ADR-049 commits): handler bodies
//! cannot take `&ContextManager` — they take `&ActorDeps` and
//! `&mut PerContextState` — so the methods they call must accept explicit
//! collaborators rather than reaching through `self`.
//!
//! This file is the tools counterpart to
//! [`crate::context::messaging_helpers`] (12b.1, 12c.1, 12c.1b),
//! [`crate::context::lifecycle_helpers`] (12c.2),
//! [`crate::context::governance_helpers`] (12c.3b),
//! [`crate::context::economy_helpers`] (12c.3a),
//! [`crate::context::trust_recovery_helpers`] (12c.3a),
//! [`crate::context::standing_helpers`] (12c.4), and
//! [`crate::context::broadcast_helpers`] (12c.4).
//!
//! # Behavior preservation
//!
//! Every hoisted free function is **behavior-preserving by construction**.
//! Its body is a verbatim copy of the legacy inherent method's body with
//! `self.X` replaced by `manager_methods::X(supervisor, ...)` for the
//! cross-domain helpers hoisted from `ContextManager` in ADR-049 commit
//! 12c.9g.1 (helper bodies migrated to direct calls in commit 12c.9g.2;
//! no `mgr` derivation).
//!
//! The legacy inherent methods on
//! [`ContextManager`](crate::context::manager::ContextManager) remain as
//! one-line forwarders; they are deleted alongside the outer shim in a
//! later ADR-049 commit when the actor handler body owns the tools
//! path directly.
//!
//! # Top-level methods hoisted (actor-handler entry points)
//!
//! [`try_consume_hard_rate_limit`], [`refund_hard_rate_limit`].
//!
//! # Not hoisted (kept as inherent methods on `ContextManager`)
//!
//! `try_consume_hard_rate_limit_blocking`,
//! `refund_hard_rate_limit_blocking`,
//! `try_consume_hard_rate_limit_from_any_context`,
//! `refund_hard_rate_limit_from_any_context`, and
//! `invoke_tool_with_economy` are reached only from FFI bridge layers
//! (`PyO3` / NAPI / `UniFFI` / WASM), not from actor handlers. They remain
//! as inherent methods on
//! [`ContextManager`](crate::context::manager::ContextManager) and are
//! out of scope for the actor-handler-driven hoist.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::tools::ToolId;
use scp_protocol::context::tools::lifecycle::ToolInvokedEvent;
use scp_protocol::context::tools::registry::ToolRegistry;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::economy::antispam::VelocityRollbackToken;
use scp_protocol::economy::policy::ObservableMetrics;
use scp_protocol::economy::types::Amount;

use crate::context::manager_methods;
use crate::context::supervisor::Supervisor;
use crate::context::tools::invoke::{
    self, InvocationError, InvokeExecuteOutcome, ToolEconomyContext, build_tool_event,
    economy_pre_check, invoke_tool_execute_and_validate, post_tool_invocation_bookkeeping,
};
use crate::economy::adapter::PaymentAdapterDyn;
use crate::economy::integration::PreparedAction;

// ---------------------------------------------------------------------------
// 1. try_consume_hard_rate_limit (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Async hard-rate-limit consume for callers already inside a tokio
/// executor where `blocking_lock` would panic.
///
/// Returns `true` if a token was consumed OR if the context is not
/// registered in the `ContextManager`. Returns `false` only when the
/// context IS registered AND the sender is over budget.
///
/// Hoisted body of the legacy
/// [`ContextManager::try_consume_hard_rate_limit`](crate::context::manager::ContextManager::try_consume_hard_rate_limit)
/// (ADR-049 commit 12c.4). Byte-identical behavior.
#[must_use]
pub async fn try_consume_hard_rate_limit(
    supervisor: &Supervisor,
    context_id: &str,
    did: &DID,
    now_secs: u64,
) -> bool {
    // ADR-049 commit 12c.9g.2 — returns `bool` so an unpopulated attach
    // slot degrades to the legacy unknown-context pass-through (`true`).
    // The contexts map accessor is reached directly through the supervisor;
    // no `mgr` derivation needed.
    let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
        return true;
    };
    let mut guard = arc.lock().await;
    let ctx = &mut *guard;
    ctx.governance.hard_rate_limit.try_consume(did, now_secs)
}

// ---------------------------------------------------------------------------
// 2. refund_hard_rate_limit (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Async hard-rate-limit refund. No-op if the context is unknown.
///
/// Hoisted body of the legacy
/// [`ContextManager::refund_hard_rate_limit`](crate::context::manager::ContextManager::refund_hard_rate_limit)
/// (ADR-049 commit 12c.4). Byte-identical behavior.
pub async fn refund_hard_rate_limit(supervisor: &Supervisor, context_id: &str, did: &DID) {
    // ADR-049 commit 12c.9g.2 — returns `()` so an unpopulated attach
    // slot degrades to a no-op with a tracing error for observability.
    // The detached-supervisor case is distinguished from the
    // unknown-context case via [`ContextError::NotInitialized`] vs
    // [`ContextError::ContextNotRegistered`] so the tracing diagnostic
    // remains specific.
    match manager_methods::get_context_arc(supervisor, context_id) {
        Ok(ctx_arc) => {
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            ctx.governance.hard_rate_limit.refund(did);
        }
        Err(scp_protocol::context::ContextError::NotInitialized(_)) => {
            tracing::error!(
                context_id,
                "refund_hard_rate_limit: Supervisor is not attached — skipping refund \
                 (contract violation; see ADR-049 commit 12c.9d)"
            );
        }
        Err(_) => {
            // Unknown context: legacy behavior is silent no-op.
        }
    }
}

// ---------------------------------------------------------------------------
// 3. try_consume_hard_rate_limit_blocking (sync; blocking_lock variant)
// ---------------------------------------------------------------------------

/// Synchronously consume one hard-rate-limit token for the given
/// `(context_id, did)` pair. Returns `true` if a token was consumed OR
/// if the context is not registered. Returns `false` only when the
/// context IS registered AND the sender is over budget.
///
/// SYNC entry point for FFI bridge tool-dispatch paths that do not flow
/// through [`invoke_tool_with_economy`]. Uses `blocking_lock` on the
/// per-context mutex; callers MUST NOT invoke this from inside an async
/// task on the same tokio runtime — doing so will panic.
///
/// Hoisted body of the legacy
/// [`ContextManager::try_consume_hard_rate_limit_blocking`]
/// (ADR-049 commit 12). Byte-identical behavior.
#[allow(clippy::significant_drop_tightening)]
#[must_use]
pub fn try_consume_hard_rate_limit_blocking(
    supervisor: &Supervisor,
    context_id: &str,
    did: &DID,
    now_secs: u64,
) -> bool {
    let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
        return true;
    };
    let ctx = arc.blocking_lock();
    ctx.governance.hard_rate_limit.try_consume(did, now_secs)
}

// ---------------------------------------------------------------------------
// 4. refund_hard_rate_limit_blocking
// ---------------------------------------------------------------------------

/// Synchronously refund one hard-rate-limit token. No-op if the context
/// is unknown. Same `blocking_lock` constraint as
/// [`try_consume_hard_rate_limit_blocking`].
///
/// Hoisted body of the legacy
/// [`ContextManager::refund_hard_rate_limit_blocking`]
/// (ADR-049 commit 12). Byte-identical behavior.
#[allow(clippy::significant_drop_tightening)]
pub fn refund_hard_rate_limit_blocking(supervisor: &Supervisor, context_id: &str, did: &DID) {
    let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
        return;
    };
    let ctx = arc.blocking_lock();
    ctx.governance.hard_rate_limit.refund(did);
}

// ---------------------------------------------------------------------------
// 5. try_consume_hard_rate_limit_from_any_context
// ---------------------------------------------------------------------------

/// Runtime-agnostic hard-rate-limit consume for sync bridge trait methods
/// that may be called from any of three tokio contexts:
///
/// 1. **No runtime active**: use `blocking_lock` directly via
///    [`try_consume_hard_rate_limit_blocking`].
/// 2. **Multi-thread runtime active**: use `block_in_place` +
///    `Handle::current().block_on(async_helper)`. `block_in_place` is
///    only valid on multi-thread runtimes.
/// 3. **Current-thread runtime active**: neither `blocking_lock` nor
///    `block_in_place` is safe. Spawn a dedicated `std::thread` with its
///    own tiny current-thread runtime, `block_on` the async helper, join
///    via an mpsc channel.
///
/// Hoisted body of the legacy
/// [`ContextManager::try_consume_hard_rate_limit_from_any_context`]
/// (ADR-049 commit 12). Byte-identical behavior.
#[must_use]
#[allow(clippy::option_if_let_else)]
pub fn try_consume_hard_rate_limit_from_any_context(
    supervisor: &Arc<Supervisor>,
    context_id: &str,
    did: &DID,
    now_secs: u64,
) -> bool {
    match tokio::runtime::Handle::try_current() {
        Err(_) => try_consume_hard_rate_limit_blocking(supervisor, context_id, did, now_secs),
        Ok(handle) => {
            use tokio::runtime::RuntimeFlavor;
            match handle.runtime_flavor() {
                RuntimeFlavor::MultiThread => tokio::task::block_in_place(|| {
                    handle.block_on(try_consume_hard_rate_limit(
                        supervisor, context_id, did, now_secs,
                    ))
                }),
                _ => run_blocking_on_dedicated_thread(
                    Arc::clone(supervisor),
                    context_id.to_owned(),
                    did.clone(),
                    now_secs,
                    /* refund = */ false,
                ),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 6. refund_hard_rate_limit_from_any_context
// ---------------------------------------------------------------------------

/// Runtime-agnostic hard-rate-limit refund. Mirrors
/// [`try_consume_hard_rate_limit_from_any_context`].
///
/// Hoisted body of the legacy
/// [`ContextManager::refund_hard_rate_limit_from_any_context`]
/// (ADR-049 commit 12). Byte-identical behavior.
#[allow(clippy::option_if_let_else)]
pub fn refund_hard_rate_limit_from_any_context(
    supervisor: &Arc<Supervisor>,
    context_id: &str,
    did: &DID,
) {
    match tokio::runtime::Handle::try_current() {
        Err(_) => {
            refund_hard_rate_limit_blocking(supervisor, context_id, did);
        }
        Ok(handle) => {
            use tokio::runtime::RuntimeFlavor;
            match handle.runtime_flavor() {
                RuntimeFlavor::MultiThread => {
                    tokio::task::block_in_place(|| {
                        handle.block_on(refund_hard_rate_limit(supervisor, context_id, did));
                    });
                }
                _ => {
                    let _ = run_blocking_on_dedicated_thread(
                        Arc::clone(supervisor),
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

/// Dedicated-thread escape hatch for current-thread runtime environments
/// where both `blocking_lock` and `block_in_place` panic. Spawns a
/// `std::thread`, builds a current-thread tokio runtime there, runs the
/// async helper, returns via mpsc.
fn run_blocking_on_dedicated_thread(
    supervisor: Arc<Supervisor>,
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
            rt.block_on(refund_hard_rate_limit(&supervisor, &context_id, &did));
            true
        } else {
            rt.block_on(try_consume_hard_rate_limit(
                &supervisor,
                &context_id,
                &did,
                now_secs,
            ))
        };
        let _ = tx.send(result);
    });
    rx.recv().unwrap_or(false)
}

// ---------------------------------------------------------------------------
// 7. ManagedToolInvocationOutput + invoke_tool_with_economy
// ---------------------------------------------------------------------------

/// Result of a successful managed tool invocation.
///
/// Hoisted from `crate::context::manager::tools::ManagedToolInvocationOutput`
/// (ADR-049 commit 12). Byte-identical shape.
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
/// Mirrors the legacy `state::tools::ToolEconomyTicket`. The
/// `#[must_use]` + `Drop` debug-assert invariant catches any future
/// refactor that leaks an unbalanced budget deduction or velocity entry.
#[must_use = "ToolEconomyTicket must be committed or rolled back — dropping leaks budget, velocity, and escrow state"]
struct ToolEconomyTicket {
    actor_did: DID,
    deducted_cost: Option<Amount>,
    velocity_token: VelocityRollbackToken,
    escrow: Option<PreparedAction>,
    policy_for_capture: Option<scp_protocol::economy::types::EconomicPolicy>,
    metrics_for_capture: ObservableMetrics,
    needs_hard_rate_limit_refund: bool,
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

fn commit_tool_economy_ticket(mut ticket: ToolEconomyTicket) -> Option<Amount> {
    ticket.consumed = true;
    ticket.needs_hard_rate_limit_refund = false;
    ticket.deducted_cost
}

#[allow(clippy::significant_drop_tightening)]
async fn rollback_tool_economy_ticket(
    supervisor: &Supervisor,
    context_id: &str,
    mut ticket: ToolEconomyTicket,
) {
    ticket.consumed = true;

    if let (Some(adapter), Some(prepared)) =
        (supervisor.payment_adapter_ref(), ticket.escrow.as_ref())
    {
        invoke::void_tool_escrow(adapter.as_ref(), prepared).await;
    }

    if let Some(entry) = supervisor.contexts_ref().get(context_id) {
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

struct Phase1Snapshot {
    handle: crate::context::ContextHandle,
    role_state: scp_protocol::context::roles::ContextRoleState,
    ticket: ToolEconomyTicket,
    ctx_gen: crate::context::state::ContextGeneration,
}

/// Invokes a tool under the full economy pipeline without holding the
/// `contexts` mutex across the executor future (spec §19.7).
///
/// Hoisted body of the legacy
/// [`ContextManager::invoke_tool_with_economy`]
/// (ADR-049 commit 12). Byte-identical behavior.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::significant_drop_tightening
)]
pub async fn invoke_tool_with_economy<F, Fut>(
    supervisor: &Supervisor,
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
    const ATTACHED_EXPECT: &str = "tools_helpers::invoke_tool_with_economy: provider slot empty";

    let clock = Arc::clone(
        supervisor
            .clock_ref()
            .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
    );
    let event_log = Arc::clone(
        supervisor
            .event_log_ref()
            .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
    );
    let key_resolver = supervisor
        .key_resolver_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
        .clone();
    let event_tx = supervisor.event_tx_ref().cloned();

    let now_secs = clock.now_secs();
    let payment_adapter: Option<Arc<dyn PaymentAdapterDyn>> =
        supervisor.payment_adapter_ref().map(Arc::clone);

    let phase1 = {
        let (mut guard, ctx_gen) = manager_methods::lock_context(supervisor, context_id)
            .await
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let ctx = &mut *guard;

        let handle = ctx.handle.clone();
        let role_state = ctx.role_state.clone();

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

        let events_snapshot = crate::context::governance_logic::event_log_entries_for_consequences(
            ctx,
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

            match economy_pre_check(&economy, invoker_did) {
                Ok(cost) => cost,
                Err(err) => {
                    ctx.governance
                        .velocity_tracker
                        .rollback(invoker_did, velocity_token);
                    ctx.governance.hard_rate_limit.refund(invoker_did);
                    return Err(invocation_error_to_context(err));
                }
            }
        };

        if action_cost.0 > 0 {
            let Some(spending) = spending_ucan else {
                ctx.governance
                    .velocity_tracker
                    .rollback(invoker_did, velocity_token);
                ctx.governance.hard_rate_limit.refund(invoker_did);
                return Err(ContextError::PermissionDenied(
                    "SCP-ECON-12060: paid action requires spending UCAN".to_owned(),
                ));
            };
            if let Err(err) = crate::context::economy_logic::validate_spending_ucan_or_error(
                spending,
                invoker_did,
                context_id,
                &mut ctx.governance.spending_nonce_tracker,
                &ctx.governance.revoked_spending_ucan_cids,
                &key_resolver,
                &*clock,
            ) {
                ctx.governance
                    .velocity_tracker
                    .rollback(invoker_did, velocity_token);
                ctx.governance.hard_rate_limit.refund(invoker_did);
                return Err(err);
            }
        }

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

        if deducted_cost.is_some()
            && let Some(spending) = spending_ucan
            && let Err(e) = scp_protocol::crypto::ucan::spending::commit_spending_ucan_nonce(
                spending,
                &mut ctx.governance.spending_nonce_tracker,
            )
        {
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
            rollback_tool_economy_ticket(supervisor, context_id, ticket).await;
            return Err(invocation_error_to_context(err));
        }
    };
    let InvokeExecuteOutcome {
        output,
        input_hash,
        output_hash,
        execution_time_ms,
    } = outcome;

    let (consequences, ticket) = {
        let Ok(mut guard) = manager_methods::relock_context(supervisor, &ctx_gen).await else {
            rollback_tool_economy_ticket(supervisor, context_id, ticket).await;
            return Err(ContextError::ContextNotRegistered(context_id.to_owned()));
        };
        let ctx = &mut *guard;

        let now = clock.now_secs();
        let events_for_consequences =
            crate::context::governance_logic::event_log_entries_for_consequences(
                ctx,
                context_id,
                now,
                event_log.as_ref(),
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

        crate::context::governance_logic::enforce_triggered_consequences(
            ctx,
            &crate::context::governance_logic::EnforceConsequencesCtx {
                context_id,
                member_did: invoker_did,
                now,
                triggered: &triggered,
                rules: &consequence_rules,
                clock: &*clock,
                event_log: event_log.as_ref(),
                event_tx: event_tx.as_ref(),
            },
        );

        (triggered, ticket)
    };

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
                    {
                        if let Ok(mut guard) =
                            manager_methods::relock_context(supervisor, &ctx_gen).await
                        {
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
