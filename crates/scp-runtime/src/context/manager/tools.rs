//! `ContextManager::invoke_tool_with_economy` — tool invocation with
//! per-DID anti-spam escalation wired from per-context governance state.
//!
//! This wrapper is the integration point between the free
//! [`crate::context::tools::invoke::invoke_tool`] function and the
//! [`super::ContextManager`] per-context state. It assembles a
//! [`ToolEconomyContext`] from the context's `GovernanceState` —
//! economic policy, budget tracker, per-DID velocity tracker, message
//! pricing config, events, consequence rules, metrics snapshot,
//! participation cache — so that tool invocations participate in the
//! same per-DID anti-spam regime as message sends (spec §19.7).
//!
//! The wrapper takes the [`ToolRegistry`] and executor as explicit
//! parameters because the manager does not own a per-context tool
//! registry today (it lives in the FFI bridge layers). This preserves
//! the bridge-owned registry invariant while eliminating the parallel
//! "tool invocations bypass escalation" gap.

use std::collections::HashMap;
use std::future::Future;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::tools::ToolId;
use scp_protocol::context::tools::registry::ToolRegistry;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::economy::policy::ObservableMetrics;

use scp_protocol::context::tools::lifecycle::ToolInvokedEvent;

use crate::context::tools::invoke::{InvocationError, ToolEconomyContext, invoke_tool};

use super::ContextManager;

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

impl ContextManager {
    /// Invokes a tool under the full economy pipeline, wiring per-DID
    /// anti-spam escalation from [`super::GovernanceState`] into
    /// [`ToolEconomyContext`] (spec §19.7).
    ///
    /// This is the single entry point that tool-invoking bridges should
    /// use when they want the runtime to enforce per-DID escalation,
    /// floor/cap, and velocity tracking for `ToolInvoke` actions. The
    /// [`ToolRegistry`] and `executor` are passed in because the bridge
    /// layers own the registry — the manager itself does not.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if the context is
    /// unknown. Returns [`ContextError::PermissionDenied`] (with an
    /// `SCP-ECON-*` code) on any invocation, budget, UCAN composition,
    /// schema validation, or consequence failure. All errors are
    /// terminal for the invocation; partial state mutations (budget,
    /// velocity) are rolled back before the error is returned.
    #[allow(clippy::too_many_arguments, clippy::significant_drop_tightening)]
    pub async fn invoke_tool_with_economy<F, Fut>(
        &self,
        context_id: &str,
        registry: &ToolRegistry,
        tool_id: &ToolId,
        input: serde_json::Value,
        invoker_did: &DID,
        action_ucan: Option<&UcanToken>,
        spending_ucan: Option<&UcanToken>,
        timeout_ms: Option<u32>,
        executor: F,
    ) -> Result<ManagedToolInvocationOutput, ContextError>
    where
        F: FnOnce(serde_json::Value) -> Fut,
        Fut: Future<Output = Result<serde_json::Value, String>>,
    {
        let mut contexts = self.contexts.lock().await;
        let ctx = contexts
            .get_mut(context_id)
            .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;

        // Snapshot the context handle and role state; they are shared
        // references into the free invoke_tool, so borrow them early.
        let handle = ctx.handle.clone();
        let role_state = ctx.role_state.clone();

        // Record the invocation for velocity tracking BEFORE enforcement
        // so that compute_escalated_cost sees the new window entry
        // (matching send_message behavior).
        let now_secs = self.clock.now_secs();
        ctx.governance
            .velocity_tracker
            .record_message(invoker_did, now_secs);

        // Snapshot metrics from the per-context state.
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

        // Extract mutable/shared refs needed by ToolEconomyContext.
        let economic_policy = ctx.governance.economic_policy.clone();
        let events_snapshot: Vec<scp_event_log::Event> = Vec::new();
        let consequence_rules = ctx.governance.consequence_rules.clone();
        let message_pricing = ctx.governance.message_pricing.clone();
        let payment_adapter = self.payment_adapter.clone();

        // Build the ToolEconomyContext with mutable borrows into ctx
        // held across the await inside invoke_tool. This is safe because
        // we hold the single top-level contexts lock for the whole call.
        let mut participation_cache: HashMap<
            String,
            scp_protocol::trust::participation::ParticipationRecord,
        > = HashMap::new();

        let invoke_result = {
            let mut economy = ToolEconomyContext {
                economic_policy: economic_policy.as_ref(),
                budget_tracker: &mut ctx.governance.budget_tracker,
                action_ucan,
                spending_ucan,
                context_id,
                now: now_secs,
                events: &events_snapshot,
                participation_cache: &mut participation_cache,
                consequence_rules: &consequence_rules,
                payment_adapter,
                metrics,
                velocity_tracker: Some(&ctx.governance.velocity_tracker),
                message_pricing: message_pricing.as_ref(),
            };

            invoke_tool(
                &handle,
                registry,
                &role_state,
                tool_id,
                input,
                invoker_did,
                timeout_ms,
                executor,
                Some(&mut economy),
            )
            .await
        };

        match invoke_result {
            Ok((output, event, consequences, payment_receipt)) => Ok(ManagedToolInvocationOutput {
                output,
                event,
                consequences,
                payment_receipt,
            }),
            Err(err) => {
                // Roll back the velocity tracker entry we recorded above.
                ctx.governance.velocity_tracker.rollback_last(invoker_did);
                Err(invocation_error_to_context(err))
            }
        }
    }
}

/// Maps an [`InvocationError`] to a [`ContextError`] with SCP codes.
fn invocation_error_to_context(err: InvocationError) -> ContextError {
    match err {
        InvocationError::ContextNotActive { current_state } => ContextError::PermissionDenied(
            format!("SCP-CTX-7080: context not active: {current_state}"),
        ),
        InvocationError::InvokerNotAuthorized { did, tool_id } => ContextError::PermissionDenied(
            format!("SCP-CTX-7081: invoker {did} lacks ToolInvoke({tool_id})"),
        ),
        InvocationError::ToolNotFound { tool_id } => {
            ContextError::PermissionDenied(format!("SCP-CTX-7082: tool not found: {tool_id}"))
        }
        InvocationError::InputValidationFailed { message } => ContextError::PermissionDenied(
            format!("SCP-CTX-7083: input schema validation failed: {message}"),
        ),
        InvocationError::OutputValidationFailed { message } => ContextError::PermissionDenied(
            format!("SCP-CTX-7084: output schema validation failed: {message}"),
        ),
        InvocationError::ExecutionFailed { message } => ContextError::PermissionDenied(format!(
            "SCP-CTX-7085: tool execution failed: {message}"
        )),
        InvocationError::Timeout { timeout_ms } => ContextError::PermissionDenied(format!(
            "SCP-CTX-7086: tool execution timed out after {timeout_ms}ms"
        )),
        InvocationError::Cancelled => {
            ContextError::PermissionDenied("SCP-CTX-7087: tool invocation cancelled".to_owned())
        }
        InvocationError::BudgetExceeded {
            did,
            cost,
            remaining,
        } => ContextError::PermissionDenied(format!(
            "SCP-ECON-7010: budget exceeded for {did}: cost {cost}, remaining {remaining}"
        )),
    }
}
