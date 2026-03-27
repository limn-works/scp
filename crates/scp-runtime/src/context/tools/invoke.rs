//! Tool invocation with full execution lifecycle.
//!
//! Implements [`invoke_tool`]: the primary entry point for executing a
//! registered tool within an SCP context. Handles context state validation,
//! UCAN capability checking, input/output schema validation, timeout
//! enforcement, cancellation, error propagation, and event log recording.
//!
//! Tool execution errors are returned in [`ToolResponse::error`](super::lifecycle::ToolResponse),
//! not as protocol-level errors. Schema validation failures are caught by
//! the SDK (this module), not by the tool itself.
//!
//! See ADR-010 in `.docs/adrs/phase-2.md` for the full design.

use std::future::Future;
use std::hash::BuildHasher;
use std::time::Duration;

use crate::context::ContextHandle;
use scp_primitives::DID;
use scp_protocol::context::ContextState;
use scp_protocol::context::roles::{Capability, ContextRoleState};
use scp_protocol::context::tools::ToolId;
use scp_protocol::context::tools::lifecycle::{
    DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS, ToolInvokedEvent, ToolStatus, sha256_json,
};
use scp_protocol::context::tools::registry::ToolRegistry;
use scp_protocol::context::tools::schema::validate_value_against_schema;
use scp_protocol::crypto::ucan::capability::CapabilityUri;
use scp_protocol::crypto::ucan::validate::{
    DidResolver, NonceTracker, ProofResolver, RevocationChecker, ValidationContext, parse_ucan,
    validate_ucan,
};
use scp_protocol::crypto::ucan::{UcanError, UcanToken};
use scp_protocol::trust::consequence::evaluate_consequence_rules;

// ---------------------------------------------------------------------------
// InvocationError
// ---------------------------------------------------------------------------

/// Errors produced by [`invoke_tool`].
///
/// These are protocol-level errors that prevent the invocation from being
/// dispatched. Tool execution errors are returned inside
/// [`ToolResponse::error`](super::lifecycle::ToolResponse) instead.
#[derive(Debug, thiserror::Error)]
pub enum InvocationError {
    /// The context is not in the Active state.
    #[error("context is not in Active state (current: {current_state})")]
    ContextNotActive {
        /// The current state of the context.
        current_state: String,
    },

    /// The invoker does not have the required capability.
    #[error(
        "invoker \"{did}\" does not have ToolInvoke(\"{tool_id}\") or ToolInvokeAll capability"
    )]
    InvokerNotAuthorized {
        /// The DID that attempted invocation.
        did: String,
        /// The tool they tried to invoke.
        tool_id: String,
    },

    /// The tool was not found in the registry.
    #[error("tool not found: \"{tool_id}\"")]
    ToolNotFound {
        /// The tool ID that was not found.
        tool_id: String,
    },

    /// Input validation failed against the tool's input schema.
    #[error("input validation failed: {message}")]
    InputValidationFailed {
        /// Description of the validation failure.
        message: String,
    },

    /// Output validation failed against the tool's output schema.
    #[error("output validation failed: {message}")]
    OutputValidationFailed {
        /// Description of the validation failure.
        message: String,
    },

    /// The tool execution timed out.
    #[error("tool execution timed out after {timeout_ms}ms")]
    Timeout {
        /// The timeout that was exceeded.
        timeout_ms: u32,
    },

    /// The tool execution was cancelled.
    #[error("tool execution was cancelled")]
    Cancelled,

    /// The tool execution failed.
    #[error("tool execution failed: {message}")]
    ExecutionFailed {
        /// Description of the execution failure.
        message: String,
    },

    /// The invoker's spending budget has been exceeded (§19.5, ADR-033).
    ///
    /// Returned when the context has an economic policy with a per-tool-invoke
    /// cost and the invoker's cumulative spending would exceed their
    /// governance-approved budget.
    ///
    /// Error code: `SCP-PERM-3030`.
    #[error("budget exceeded for invoker \"{did}\": cost {cost}, remaining {remaining}")]
    BudgetExceeded {
        /// The DID that attempted invocation.
        did: String,
        /// The cost of the tool invocation.
        cost: u64,
        /// The remaining budget for the invoker.
        remaining: u64,
    },
}

// ---------------------------------------------------------------------------
// Economy context for tool invocation
// ---------------------------------------------------------------------------

/// Optional economy parameters for tool invocation.
///
/// When provided, `invoke_tool` enforces budget checks before execution
/// and performs post-invocation bookkeeping (participation record update,
/// consequence rule evaluation). Pass `None` when economy is not configured
/// for the context.
pub struct ToolEconomyContext<'a, S: BuildHasher = std::hash::RandomState> {
    /// The context's economic policy (from `PerContextState.governance.economic_policy`).
    pub economic_policy: Option<&'a scp_protocol::economy::types::EconomicPolicy>,
    /// Mutable reference to the invoker's budget tracker.
    pub budget_tracker: &'a mut scp_protocol::economy::budget::MemberBudgetTracker,
    /// Action UCAN for AND-composition check (§19.5). `None` if no action UCAN presented.
    pub action_ucan: Option<&'a UcanToken>,
    /// Spending UCAN for AND-composition check (§19.5). `None` if no spending UCAN presented.
    pub spending_ucan: Option<&'a UcanToken>,
    /// Context ID for bookkeeping.
    pub context_id: &'a str,
    /// Current timestamp (seconds since epoch).
    pub now: u64,
    /// Event log entries for consequence evaluation.
    pub events: &'a [scp_event_log::Event],
    /// Participation cache for standing evaluation.
    pub participation_cache: &'a mut std::collections::HashMap<
        String,
        scp_protocol::trust::participation::ParticipationRecord,
        S,
    >,
    /// Consequence rules from the context's governance state.
    pub consequence_rules: &'a [scp_protocol::trust::consequence::ConsequenceRule],
    /// Optional payment adapter for the 9-step payment flow (spec §19.2.2, #1537).
    ///
    /// When `Some`, `invoke_tool` runs `prepare_paid_action` + `process_paid_action`
    /// before tool execution. When `None`, only budget enforcement runs.
    pub payment_adapter: Option<std::sync::Arc<dyn crate::economy::adapter::PaymentAdapterDyn>>,
    /// Observable metrics for dynamic cost evaluation. Populated from
    /// `PerContextState` by the caller so that tool economy uses real
    /// metrics instead of zeros.
    pub metrics: scp_protocol::economy::policy::ObservableMetrics,
}

// ---------------------------------------------------------------------------
// invoke_tool
// ---------------------------------------------------------------------------

/// Invokes a tool within a context, performing full lifecycle validation.
///
/// Execution flow:
/// 1. Validates context state is [`Active`](ContextState::Active).
/// 2. Validates invoker has [`ToolInvoke(tool_id)`](Capability::ToolInvoke)
///    or [`ToolInvokeAll`](Capability::ToolInvokeAll) capability via UCAN.
/// 3. Looks up the tool in the registry.
/// 4. Validates input against the tool's input schema.
///    - 4a. Economy: checks budget and UCAN composition (if economy context provided).
/// 5. Calls the tool implementation via the `executor` function.
/// 6. Validates output against the tool's output schema.
///    - 6a. Post-invocation bookkeeping — participation + consequences.
/// 7. Builds a [`ToolInvokedEvent`] for the caller to append to the event log.
/// 8. Returns the tool output and any triggered consequences.
///
/// # Timeout handling
///
/// The `timeout_ms` parameter specifies the maximum time to wait for the tool
/// to complete. If the tool does not complete within the timeout, a
/// [`InvocationError::Timeout`] is returned. The timeout is clamped to the
/// hard protocol maximum of [`MAX_TIMEOUT_MS`] (300,000ms / 5 minutes).
///
/// # Cancellation
///
/// Cancellation is handled externally via [`ToolCancel`](super::lifecycle::ToolCancel)
/// messages. This function supports cancellation through a
/// `cancellation_token` future that resolves when cancellation is requested.
///
/// # Errors
///
/// Returns [`InvocationError`] on protocol-level validation failures,
/// budget exceeded, or UCAN composition failures.
///
/// See ADR-010 acceptance criterion 3 (`invoke_tool`).
#[allow(clippy::too_many_arguments)]
pub async fn invoke_tool<F, Fut, S: BuildHasher>(
    context: &ContextHandle,
    registry: &ToolRegistry,
    role_state: &ContextRoleState,
    tool_id: &ToolId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: F,
    mut economy: Option<&mut ToolEconomyContext<'_, S>>,
) -> Result<
    (
        serde_json::Value,
        ToolInvokedEvent,
        Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
        Option<crate::economy::adapter::PaymentReceipt>,
    ),
    InvocationError,
>
where
    F: FnOnce(serde_json::Value) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
{
    let start = std::time::Instant::now();

    // 1. Validate context state is Active.
    let state = context.state().await;
    if state != ContextState::Active {
        return Err(InvocationError::ContextNotActive {
            current_state: state.to_string(),
        });
    }

    // 2. Validate invoker has ToolInvoke(tool_id) or ToolInvokeAll capability.
    if !has_tool_invoke_capability(role_state, invoker_did, tool_id) {
        return Err(InvocationError::InvokerNotAuthorized {
            did: invoker_did.to_string(),
            tool_id: tool_id.to_owned(),
        });
    }

    // 3. Look up the tool in the registry.
    let registration = registry
        .get(tool_id)
        .ok_or_else(|| InvocationError::ToolNotFound {
            tool_id: tool_id.to_owned(),
        })?;

    // 4. Validate input against the tool's input schema.
    validate_value_against_schema(&input, &registration.schema.input_schema)
        .map_err(|msg| InvocationError::InputValidationFailed { message: msg })?;

    // 4a. Economy pre-check (#1537).
    let action_cost = economy
        .as_mut()
        .map(|econ| economy_pre_check(econ, invoker_did))
        .transpose()?;

    // 4b. Payment flow (#1537, #1596): 9-step paid action for tool invocations.
    // Runs after budget check but before tool execution. Only triggers when
    // a payment adapter is configured AND cost > 0.
    // If payment fails, roll back the budget deducted by economy_pre_check.
    // The receipt is returned to the caller for event log recording.
    let payment_receipt = if let Some(ref econ) = economy
        && let (Some(adapter), Some(policy)) = (&econ.payment_adapter, econ.economic_policy)
    {
        let remaining = econ.budget_tracker.remaining(invoker_did);
        match execute_tool_payment(
            adapter.as_ref(),
            policy,
            econ.context_id,
            invoker_did,
            remaining,
        )
        .await
        {
            Ok(receipt) => receipt,
            Err(payment_err) => {
                // Restore the budget deducted by check_tool_economy.
                if let Some(cost) = action_cost
                    && let Some(ref mut econ) = economy
                {
                    econ.budget_tracker.grant(invoker_did, cost);
                }
                return Err(payment_err);
            }
        }
    } else {
        None
    };

    // 5. Execute the tool with timeout.
    let effective_timeout = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS).min(MAX_TIMEOUT_MS);
    let timeout_duration = Duration::from_millis(u64::from(effective_timeout));
    let execution_result = tokio::time::timeout(timeout_duration, executor(input.clone())).await;
    let output = match execution_result {
        Ok(Ok(output)) => output,
        Ok(Err(exec_err)) => return Err(InvocationError::ExecutionFailed { message: exec_err }),
        Err(_elapsed) => {
            return Err(InvocationError::Timeout {
                timeout_ms: effective_timeout,
            });
        }
    };

    // 6. Validate output + post-invocation bookkeeping (#1530, #1531).
    validate_value_against_schema(&output, &registration.schema.output_schema)
        .map_err(|msg| InvocationError::OutputValidationFailed { message: msg })?;
    let triggered = economy
        .as_mut()
        .map(|econ| economy_post_check(econ, invoker_did))
        .unwrap_or_default();

    // 7-8. Build event + return (#1596: receipt returned to caller).
    let event = build_tool_event(tool_id, invoker_did, start, &input, &output, action_cost);
    Ok((output, event, triggered, payment_receipt))
}

/// Runs economy pre-checks (budget enforcement + UCAN AND-composition).
///
/// Returns the evaluated action cost for inclusion in the `ToolInvokedEvent`.
fn economy_pre_check<S: BuildHasher>(
    economy: &mut ToolEconomyContext<'_, S>,
    invoker_did: &DID,
) -> Result<scp_protocol::economy::types::Amount, InvocationError> {
    check_tool_economy(economy.economic_policy, economy.budget_tracker, invoker_did)?;
    let cost = economy
        .economic_policy
        .and_then(|policy| {
            scp_protocol::economy::policy::evaluate_cost(
                policy,
                &scp_protocol::economy::types::PaidActionType::ToolInvoke,
                &economy.metrics,
            )
        })
        .unwrap_or(scp_protocol::economy::types::Amount::new(0));
    if cost.0 > 0 {
        check_tool_ucan_composition(cost, economy.action_ucan, economy.spending_ucan)?;
    }
    Ok(cost)
}

/// Runs post-invocation bookkeeping (participation + consequence evaluation).
fn economy_post_check<S: BuildHasher>(
    economy: &mut ToolEconomyContext<'_, S>,
    invoker_did: &DID,
) -> Vec<scp_protocol::trust::consequence::TriggeredConsequence> {
    post_tool_invocation_bookkeeping(
        economy.events,
        invoker_did,
        economy.context_id,
        economy.now,
        economy.participation_cache,
        economy.consequence_rules,
    )
}

/// Builds a [`ToolInvokedEvent`] from invocation metadata.
fn build_tool_event(
    tool_id: &ToolId,
    invoker_did: &DID,
    start: std::time::Instant,
    input: &serde_json::Value,
    output: &serde_json::Value,
    cost: Option<scp_protocol::economy::types::Amount>,
) -> ToolInvokedEvent {
    ToolInvokedEvent {
        request_id: uuid::Uuid::new_v4().to_string(),
        tool_id: tool_id.to_owned(),
        invoker_did: invoker_did.clone(),
        status: ToolStatus::Success,
        execution_time_ms: elapsed_ms(start),
        input_hash: sha256_json(input),
        output_hash: Some(sha256_json(output)),
        cost,
    }
}

/// Invokes a tool with cancellation support.
///
/// Same as [`invoke_tool`] but accepts a cancellation future. If the
/// cancellation future resolves before the tool completes, the invocation
/// returns [`InvocationError::Cancelled`].
///
/// Cancellation is best-effort: if the tool completes before the cancel
/// signal, the successful result is returned.
///
/// # Errors
///
/// Returns [`InvocationError`] on protocol-level validation failures,
/// timeout, cancellation, budget exceeded, or UCAN composition failures.
#[allow(clippy::too_many_arguments)]
pub async fn invoke_tool_with_cancellation<F, Fut, C, CFut, S: BuildHasher>(
    context: &ContextHandle,
    registry: &ToolRegistry,
    role_state: &ContextRoleState,
    tool_id: &ToolId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: F,
    cancellation: C,
    mut economy: Option<&mut ToolEconomyContext<'_, S>>,
) -> Result<
    (
        serde_json::Value,
        ToolInvokedEvent,
        Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
        Option<crate::economy::adapter::PaymentReceipt>,
    ),
    InvocationError,
>
where
    F: FnOnce(serde_json::Value) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
    C: FnOnce() -> CFut,
    CFut: Future<Output = ()>,
{
    let start = std::time::Instant::now();

    // 1-4: Validate context, capability, tool, schema (same as invoke_tool).
    let state = context.state().await;
    if state != ContextState::Active {
        return Err(InvocationError::ContextNotActive {
            current_state: state.to_string(),
        });
    }
    if !has_tool_invoke_capability(role_state, invoker_did, tool_id) {
        return Err(InvocationError::InvokerNotAuthorized {
            did: invoker_did.to_string(),
            tool_id: tool_id.to_owned(),
        });
    }
    let registration = registry
        .get(tool_id)
        .ok_or_else(|| InvocationError::ToolNotFound {
            tool_id: tool_id.to_owned(),
        })?;
    validate_value_against_schema(&input, &registration.schema.input_schema)
        .map_err(|msg| InvocationError::InputValidationFailed { message: msg })?;

    // 4a. Economy pre-check (#1537).
    let action_cost = economy
        .as_mut()
        .map(|econ| economy_pre_check(econ, invoker_did))
        .transpose()?;

    // 4b. Payment flow (#1537, #1596): 9-step paid action for tool invocations.
    // If payment fails, roll back the budget deducted by economy_pre_check.
    let payment_receipt = if let Some(ref econ) = economy
        && let (Some(adapter), Some(policy)) = (&econ.payment_adapter, econ.economic_policy)
    {
        let remaining = econ.budget_tracker.remaining(invoker_did);
        match execute_tool_payment(
            adapter.as_ref(),
            policy,
            econ.context_id,
            invoker_did,
            remaining,
        )
        .await
        {
            Ok(receipt) => receipt,
            Err(payment_err) => {
                // Restore the budget deducted by check_tool_economy.
                if let Some(cost) = action_cost
                    && let Some(ref mut econ) = economy
                {
                    econ.budget_tracker.grant(invoker_did, cost);
                }
                return Err(payment_err);
            }
        }
    } else {
        None
    };

    // 5. Execute with timeout and cancellation.
    let effective_timeout = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS).min(MAX_TIMEOUT_MS);
    let timeout_duration = Duration::from_millis(u64::from(effective_timeout));
    let exec_fut = executor(input.clone());
    let cancel_fut = cancellation();
    tokio::pin!(exec_fut);
    tokio::pin!(cancel_fut);
    let execution_result = tokio::time::timeout(timeout_duration, async {
        tokio::select! {
            result = &mut exec_fut => result,
            () = &mut cancel_fut => Err("cancelled".to_owned()),
        }
    })
    .await;
    let output = match execution_result {
        Ok(Ok(output)) => output,
        Ok(Err(msg)) if msg == "cancelled" => return Err(InvocationError::Cancelled),
        Ok(Err(exec_err)) => return Err(InvocationError::ExecutionFailed { message: exec_err }),
        Err(_elapsed) => {
            return Err(InvocationError::Timeout {
                timeout_ms: effective_timeout,
            });
        }
    };

    // 6. Validate output + post-invocation bookkeeping.
    validate_value_against_schema(&output, &registration.schema.output_schema)
        .map_err(|msg| InvocationError::OutputValidationFailed { message: msg })?;
    let triggered = economy
        .as_mut()
        .map(|econ| economy_post_check(econ, invoker_did))
        .unwrap_or_default();

    // 7. Build event + return (#1596: receipt returned to caller).
    let event = build_tool_event(tool_id, invoker_did, start, &input, &output, action_cost);
    Ok((output, event, triggered, payment_receipt))
}

// ---------------------------------------------------------------------------
// Economy pre-check for tool invocation (#1537)
// ---------------------------------------------------------------------------

/// Checks economic policy constraints and UCAN spending authorization
/// before tool invocation.
///
/// If the context has an economic policy with a per-tool-invoke cost,
/// records the spend against the invoker's budget. Returns
/// [`InvocationError::BudgetExceeded`] if the spend exceeds the budget.
///
/// Also validates UCAN composition: if the action has a cost, a spending
/// UCAN must be provided alongside the action UCAN (§19.5).
///
/// Call this BEFORE [`invoke_tool`] to enforce economy (#1537).
///
/// # Errors
///
/// Returns [`InvocationError::BudgetExceeded`] if the invoker's cumulative
/// spending would exceed their governance-approved budget.
pub fn check_tool_economy(
    economic_policy: Option<&scp_protocol::economy::types::EconomicPolicy>,
    budget_tracker: &mut scp_protocol::economy::budget::MemberBudgetTracker,
    invoker_did: &DID,
) -> Result<(), InvocationError> {
    if let Some(policy) = economic_policy {
        // Standalone callers (tests, direct API) pass zero metrics.
        // Production callers use ToolEconomyContext.metrics via
        // economy_pre_check which carries real ObservableMetrics from
        // PerContextState. This function evaluates the base cost for
        // budget enforcement; dynamic pricing is handled by the caller.
        let metrics = scp_protocol::economy::policy::ObservableMetrics {
            context_message_rate: 0,
            member_count: 0,
            relay_queue_depth: 0,
            time_of_day: 0,
            sender_velocity: 0,
            storage_usage: 0,
        };
        if let Some(cost) = scp_protocol::economy::policy::evaluate_cost(
            policy,
            &scp_protocol::economy::types::PaidActionType::ToolInvoke,
            &metrics,
        ) {
            // No auto-grant — budget must be explicitly approved via
            // ApproveSpend governance action. If no budget exists, fail
            // with BudgetExceeded error.
            if !budget_tracker.has_budget(invoker_did) {
                return Err(InvocationError::BudgetExceeded {
                    did: invoker_did.to_string(),
                    cost: cost.0,
                    remaining: 0,
                });
            }
            // Record spend against invoker budget (§19.5, ADR-033).
            budget_tracker
                .record_spend(invoker_did, cost)
                .map_err(|_| InvocationError::BudgetExceeded {
                    did: invoker_did.to_string(),
                    cost: cost.0,
                    remaining: budget_tracker.remaining(invoker_did).0,
                })?;
        }
    }
    Ok(())
}

/// Post-invocation bookkeeping: participation record update and consequence evaluation.
///
/// Called after a successful tool invocation to update governance state.
/// `compute_participation_record` refreshes the cache for standing evaluation
/// (#1530). `evaluate_consequence_rules` checks whether the tool invocation
/// triggered any consequence rules (#1531).
pub fn post_tool_invocation_bookkeeping<S: std::hash::BuildHasher>(
    events: &[scp_event_log::Event],
    invoker_did: &DID,
    context_id: &str,
    now: u64,
    participation_cache: &mut std::collections::HashMap<
        String,
        scp_protocol::trust::participation::ParticipationRecord,
        S,
    >,
    consequence_rules: &[scp_protocol::trust::consequence::ConsequenceRule],
) -> Vec<scp_protocol::trust::consequence::TriggeredConsequence> {
    // Update participation record after tool execution (#1530).
    if !events.is_empty()
        && let Ok(record) = scp_protocol::trust::participation::compute_participation_record(
            events,
            invoker_did.as_ref(),
            context_id,
            [0u8; 32],
            now,
        )
    {
        participation_cache.insert(invoker_did.to_string(), record);
    }

    // Evaluate consequence rules after tool execution (#1531).
    // The caller is responsible for enforcing triggered consequences via
    // enforce_triggered_consequences on the PerContextState.
    evaluate_consequence_rules(consequence_rules, events, invoker_did.as_ref(), now)
}

/// Validates UCAN AND-composition for tool invocations with economic cost.
///
/// If the tool invocation has a cost (from the context's economic policy),
/// checks that the invoker has both an action UCAN and a spending UCAN.
/// Called as part of the tool invocation economy pre-check (#1537, §19.5).
///
/// # Errors
///
/// Returns [`InvocationError::ExecutionFailed`] if the AND-composition check
/// fails (missing action UCAN or missing spending UCAN for a paid action).
pub fn check_tool_ucan_composition(
    action_cost: scp_protocol::economy::types::Amount,
    action_ucan: Option<&UcanToken>,
    spending_ucan: Option<&UcanToken>,
) -> Result<(), InvocationError> {
    // Convert economy Amount to UCAN spending Amount (both are u64 wrappers).
    let ucan_amount = scp_protocol::crypto::ucan::spending::Amount(action_cost.0);
    scp_protocol::crypto::ucan::spending::check_and_composition(
        action_ucan,
        spending_ucan,
        ucan_amount,
        "tool:invoke",
    )
    .map_err(|e| InvocationError::ExecutionFailed {
        message: format!("UCAN spending composition check failed: {e}"),
    })
}

// ---------------------------------------------------------------------------
// Payment flow for tool invocations (#1537)
// ---------------------------------------------------------------------------

/// Wrapper that bridges `&dyn PaymentAdapterDyn` to `PaymentAdapter` for the
/// generic `prepare_paid_action` / `process_paid_action` functions.
struct ToolPaymentBridge<'a>(&'a dyn crate::economy::adapter::PaymentAdapterDyn);

#[allow(clippy::similar_names)] // payer/payee is the domain language
impl crate::economy::adapter::PaymentAdapter for ToolPaymentBridge<'_> {
    fn adapter_id(&self) -> &str {
        self.0.adapter_id()
    }
    fn capabilities(&self) -> crate::economy::adapter::AdapterCapabilities {
        self.0.capabilities()
    }
    async fn authorize(
        &self,
        payer: &DID,
        payee: &DID,
        amount: scp_protocol::economy::types::Amount,
        currency: scp_protocol::economy::types::CurrencyCode,
        metadata: crate::economy::adapter::PaymentMetadata,
    ) -> Result<crate::economy::adapter::PaymentAuthorization, crate::economy::adapter::PaymentError>
    {
        self.0
            .authorize_dyn(payer, payee, amount, currency, metadata)
            .await
    }
    async fn capture(
        &self,
        auth: &crate::economy::adapter::PaymentAuthorization,
    ) -> Result<crate::economy::adapter::PaymentReceipt, crate::economy::adapter::PaymentError>
    {
        self.0.capture_dyn(auth).await
    }
    async fn void(
        &self,
        auth: &crate::economy::adapter::PaymentAuthorization,
    ) -> Result<(), crate::economy::adapter::PaymentError> {
        self.0.void_dyn(auth).await
    }
    async fn verify_authorization(
        &self,
        auth: &crate::economy::adapter::PaymentAuthorization,
    ) -> Result<(), crate::economy::adapter::PaymentError> {
        self.0.verify_authorization_dyn(auth).await
    }
    async fn verify(
        &self,
        receipt: &crate::economy::adapter::PaymentReceipt,
    ) -> Result<crate::economy::adapter::VerificationResult, crate::economy::adapter::PaymentError>
    {
        self.0.verify_dyn(receipt).await
    }
    async fn refund(
        &self,
        receipt: &crate::economy::adapter::PaymentReceipt,
        amount: Option<scp_protocol::economy::types::Amount>,
    ) -> Result<crate::economy::adapter::RefundConfirmation, crate::economy::adapter::PaymentError>
    {
        self.0.refund_dyn(receipt, amount).await
    }
}

/// Executes the 9-step payment flow for tool invocations (#1537, #1596, spec §19.2.2).
///
/// Called from `invoke_tool` after the economy pre-check (budget + UCAN
/// composition) but before tool execution. Uses the adapter from
/// `ToolEconomyContext::payment_adapter`. Skips if no economic policy or
/// zero cost.
///
/// Returns the payment receipt when a payment was captured, `None` when
/// the cost was zero or no payment was needed. The caller is responsible
/// for recording the receipt in the event log (matching the pattern in
/// `ContextManager::execute_paid_action`).
///
/// # Errors
///
/// Returns [`InvocationError::BudgetExceeded`] on any payment flow failure.
async fn execute_tool_payment(
    adapter: &dyn crate::economy::adapter::PaymentAdapterDyn,
    policy: &scp_protocol::economy::types::EconomicPolicy,
    context_id: &str,
    invoker_did: &DID,
    budget_remaining: scp_protocol::economy::types::Amount,
) -> Result<Option<crate::economy::adapter::PaymentReceipt>, InvocationError> {
    let metrics = scp_protocol::economy::policy::ObservableMetrics {
        member_count: 0,
        context_message_rate: 0,
        relay_queue_depth: 0,
        time_of_day: 0,
        sender_velocity: 0,
        storage_usage: 0,
    };

    let cost = scp_protocol::economy::policy::evaluate_cost(
        policy,
        &scp_protocol::economy::types::PaidActionType::ToolInvoke,
        &metrics,
    );
    let Some(cost) = cost.filter(|c| c.0 > 0) else {
        return Ok(None);
    };

    let bridge = ToolPaymentBridge(adapter);
    let metadata = crate::economy::adapter::PaymentMetadata {
        action_type: scp_protocol::economy::types::PaidActionType::ToolInvoke,
        context_id: Some(context_id.to_owned()),
        idempotency_key: *uuid::Uuid::new_v4().as_bytes(),
    };

    // Steps 1-4: Prepare (evaluate cost + authorize).
    let prepared = crate::economy::integration::prepare_paid_action(
        &bridge,
        Some(policy),
        scp_protocol::economy::types::PaidActionType::ToolInvoke,
        invoker_did,
        Some(context_id.to_owned()),
        &metrics,
        metadata,
        Vec::new(),
    )
    .await
    .map_err(|_| InvocationError::BudgetExceeded {
        did: invoker_did.to_string(),
        cost: cost.0,
        remaining: budget_remaining.0,
    })?;

    // Steps 5-8: Process (verify auth + capture).
    let processed = crate::economy::integration::process_paid_action(
        &bridge,
        Some(policy),
        &prepared.envelope,
        &metrics,
        |payload| async move { Ok(payload) },
    )
    .await
    .map_err(|_| InvocationError::BudgetExceeded {
        did: invoker_did.to_string(),
        cost: cost.0,
        remaining: budget_remaining.0,
    })?;

    if let Some(receipt) = &processed.receipt {
        tracing::debug!(
            receipt_id = %hex::encode(receipt.receipt_id),
            adapter_id = %receipt.adapter_id,
            "tool invocation payment receipt captured"
        );
    }

    Ok(processed.receipt)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Converts an [`std::time::Instant`] elapsed duration to milliseconds as `u64`.
///
/// Saturates at `u64::MAX` if the elapsed duration exceeds `u64` range (which
/// would require ~584 million years).
#[allow(clippy::cast_possible_truncation)]
fn elapsed_ms(start: std::time::Instant) -> u64 {
    let millis = start.elapsed().as_millis();
    if millis > u128::from(u64::MAX) {
        u64::MAX
    } else {
        millis as u64
    }
}

// ---------------------------------------------------------------------------
// Capability check helpers
// ---------------------------------------------------------------------------

/// Checks whether a member has the `ToolInvoke(tool_id)` or `ToolInvokeAll`
/// capability.
///
/// This is the integration point between the invocation module and the
/// UCAN-based role system (ADR-009).
#[must_use]
pub fn has_tool_invoke_capability(role_state: &ContextRoleState, did: &str, tool_id: &str) -> bool {
    // Check for ToolInvokeAll first (broader permission).
    if role_state.member_has_capability(did, &Capability::ToolInvokeAll) {
        return true;
    }
    // Check for specific ToolInvoke(tool_id).
    role_state.member_has_capability(did, &Capability::ToolInvoke(tool_id.to_owned()))
}

// ---------------------------------------------------------------------------
// UCAN validation at tool invocation boundary (#319)
// ---------------------------------------------------------------------------

/// Validates a UCAN token for tool invocation authorization.
///
/// Parses the encoded JWT token and runs the full 11-step ADR-016 validation
/// pipeline, requiring `tool_invoke:{tool_name}` or `tool_invoke:*` capability
/// scoped to the given context.
///
/// This is the primary authorization gate for tool invocations. Role-based
/// `has_tool_invoke_capability` remains as defense-in-depth.
///
/// # Arguments
///
/// * `encoded_token` — JWT-encoded UCAN token.
/// * `context_id` — The context ID the tool belongs to.
/// * `tool_name` — The name of the tool being invoked.
/// * `ctx` — The validation context with resolvers, trackers, and ceiling.
///
/// # Errors
///
/// Returns [`UcanError`] if the token is malformed, expired, revoked, lacks
/// the required capability, or fails any of the 11 validation steps.
///
/// See spec §6.2, §8, ADR-016, and issue #319.
pub fn validate_tool_invocation_ucan<D, N, R, P, S>(
    encoded_token: &str,
    context_id: &str,
    tool_name: &str,
    ctx: &mut ValidationContext<'_, D, N, R, P, S>,
) -> Result<(), UcanError>
where
    D: DidResolver,
    N: NonceTracker,
    R: RevocationChecker,
    P: ProofResolver,
    S: BuildHasher,
{
    let parsed = parse_ucan(encoded_token)?;
    let required_cap = CapabilityUri::new(context_id, "tool_invoke", tool_name);
    validate_ucan(&parsed, &required_cap, ctx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use scp_protocol::context::ContextParams;
    use scp_protocol::context::roles::{CapabilityCeiling, ContextRoleState};
    use scp_protocol::context::tools::registry::{ToolRegistration, ToolSchema, register_tool};

    /// Creates a test capability ceiling with all capabilities.
    fn test_ceiling() -> CapabilityCeiling {
        CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ToolRegister,
            Capability::ToolInvokeAll,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
        ])
    }

    /// Creates a `ContextRoleState` with a creator that has admin (all) capabilities.
    fn test_role_state(creator_did: &str) -> ContextRoleState {
        ContextRoleState::new(
            "ctx-test",
            creator_did,
            test_ceiling(),
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap()
    }

    /// Creates a `ContextRoleState` with an additional member that has limited
    /// capabilities (no `ToolInvoke`).
    fn test_role_state_with_no_invoke_member(
        creator_did: &str,
        member_did: &str,
    ) -> ContextRoleState {
        let mut state = test_role_state(creator_did);
        state.members.insert(member_did.to_owned());
        // Assign only MessagesRead/Write, no tool invoke.
        let member_caps: HashSet<Capability> =
            [Capability::MessagesRead, Capability::MessagesWrite]
                .into_iter()
                .collect();
        state
            .member_capabilities
            .insert(member_did.to_owned(), member_caps);
        state
    }

    /// Creates a valid tool registration and registers it in a fresh registry.
    fn setup_registry_with_tool(
        role_state: &ContextRoleState,
        registrant_did: &str,
    ) -> ToolRegistry {
        let mut registry = ToolRegistry::new();
        let registration = ToolRegistration {
            tool_id: "calculator".to_owned(),
            name: "Calculator".to_owned(),
            description: "A simple calculator".to_owned(),
            schema: ToolSchema {
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "a": {"type": "number"},
                        "b": {"type": "number"}
                    }
                }),
                output_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "result": {"type": "number"}
                    }
                }),
            },
            implementation_hash: [0xAA; 32],
            test_vectors: vec![],
            operator_did: "did:dht:z6MkOperator".into(),
            cost: None,
            registered_at: 0,
            signature: Vec::new(),
        };
        register_tool(&mut registry, role_state, registration, registrant_did).unwrap();
        registry
    }

    /// Creates an active context handle (transitions from Creating to Active).
    async fn active_context() -> ContextHandle {
        let handle = ContextHandle::new("ctx-invoke-test".to_owned(), ContextParams::default());
        handle.transition_to(&ContextState::Active).await.unwrap();
        handle
    }

    /// A simple async executor that adds two numbers.
    async fn add_executor(input: serde_json::Value) -> Result<serde_json::Value, String> {
        let a = input
            .get("a")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| "missing field 'a'".to_owned())?;
        let b = input
            .get("b")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| "missing field 'b'".to_owned())?;
        Ok(serde_json::json!({"result": a + b}))
    }

    // -----------------------------------------------------------------------
    // invoke_tool: happy path
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_tool_succeeds_with_valid_invocation() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        let input = serde_json::json!({"a": 3, "b": 4});
        let result = invoke_tool(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            input,
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut ToolEconomyContext<'_>>,
        )
        .await;

        assert!(result.is_ok(), "invoke_tool should succeed: {result:?}");
        let (output, event, _consequences, _receipt) = result.unwrap();
        assert_eq!(output, serde_json::json!({"result": 7.0}));
        assert_eq!(event.tool_id, "calculator");
        assert_eq!(event.invoker_did, creator_did);
        assert_eq!(event.status, ToolStatus::Success);
        assert!(event.output_hash.is_some());
        assert!(!event.input_hash.is_empty());
    }

    // -----------------------------------------------------------------------
    // invoke_tool: context not Active
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_tool_rejects_when_context_not_active() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);

        // Context is in Creating state (not Active).
        let context = ContextHandle::new("ctx-test".to_owned(), ContextParams::default());

        let result = invoke_tool(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut ToolEconomyContext<'_>>,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::ContextNotActive { .. }),
            "expected ContextNotActive, got {err:?}"
        );
        assert!(err.to_string().contains("Creating"));
    }

    // -----------------------------------------------------------------------
    // invoke_tool: invoker without ToolInvoke capability
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_tool_rejects_invoker_without_tool_invoke_capability() {
        let creator_did = "did:dht:z6MkCreator";
        let member_did = "did:dht:z6MkMember";
        let role_state = test_role_state_with_no_invoke_member(creator_did, member_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        let result = invoke_tool(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member_did),
            None,
            add_executor,
            None::<&mut ToolEconomyContext<'_>>,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::InvokerNotAuthorized { .. }),
            "expected InvokerNotAuthorized, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_tool: tool not found
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_tool_rejects_unknown_tool() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = ToolRegistry::new(); // Empty registry
        let context = active_context().await;

        let result = invoke_tool(
            &context,
            &registry,
            &role_state,
            &"nonexistent-tool".to_owned(),
            serde_json::json!({}),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut ToolEconomyContext<'_>>,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::ToolNotFound { .. }),
            "expected ToolNotFound, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_tool: input schema validation failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_tool_rejects_invalid_input_schema() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        // Input schema expects an object, passing a string instead.
        let result = invoke_tool(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!("not an object"),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut ToolEconomyContext<'_>>,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::InputValidationFailed { .. }),
            "expected InputValidationFailed, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_tool: timeout
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_tool_timeout_synthesizes_timeout_error() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        // Executor that sleeps for 5 seconds (will be timed out).
        let slow_executor = |_input: serde_json::Value| async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(serde_json::json!({"result": 42}))
        };

        let result = invoke_tool(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            Some(50), // 50ms timeout -- will expire before the 5s sleep.
            slow_executor,
            None::<&mut ToolEconomyContext<'_>>,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::Timeout { timeout_ms: 50 }),
            "expected Timeout with 50ms, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_tool: cancellation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_tool_cancellation_returns_cancelled_status() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        // Executor that sleeps for 5 seconds (will be cancelled).
        let slow_executor = |_input: serde_json::Value| async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(serde_json::json!({"result": 42}))
        };

        // Cancellation fires after 10ms.
        let cancel = || async {
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        let result = invoke_tool_with_cancellation(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            slow_executor,
            cancel,
            None::<&mut ToolEconomyContext<'_>>,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::Cancelled),
            "expected Cancelled, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_tool: execution failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_tool_execution_failure_propagates_error() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        // Executor that always fails.
        let failing_executor = |_input: serde_json::Value| async {
            Err::<serde_json::Value, String>("computation exploded".to_owned())
        };

        let result = invoke_tool(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            failing_executor,
            None::<&mut ToolEconomyContext<'_>>,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::ExecutionFailed { .. }),
            "expected ExecutionFailed, got {err:?}"
        );
        assert!(err.to_string().contains("computation exploded"));
    }

    // -----------------------------------------------------------------------
    // invoke_tool: output schema validation failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_tool_rejects_invalid_output_schema() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        // Executor that returns a string instead of an object.
        let bad_output_executor = |_input: serde_json::Value| async {
            Ok::<serde_json::Value, String>(serde_json::json!("not an object"))
        };

        let result = invoke_tool(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            bad_output_executor,
            None::<&mut ToolEconomyContext<'_>>,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::OutputValidationFailed { .. }),
            "expected OutputValidationFailed, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_tool: event log records hashes, not full data
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_tool_event_contains_hashes_not_full_data() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        let input = serde_json::json!({"a": 10, "b": 20});

        let (output, event, _consequences, _receipt) = invoke_tool(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            input.clone(),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut ToolEconomyContext<'_>>,
        )
        .await
        .unwrap();

        // Verify hashes are present and correct.
        let expected_input_hash = sha256_json(&input);
        let expected_output_hash = sha256_json(&output);

        assert_eq!(event.input_hash, expected_input_hash);
        assert_eq!(event.output_hash, Some(expected_output_hash));

        // Hashes are 64-char hex strings (SHA-256).
        assert_eq!(event.input_hash.len(), 64);
        assert!(event.input_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // invoke_tool: context in Closing state
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_tool_rejects_closing_context() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);

        let context = ContextHandle::new("ctx-closing".to_owned(), ContextParams::default());
        context.transition_to(&ContextState::Active).await.unwrap();
        context.transition_to(&ContextState::Closing).await.unwrap();

        let result = invoke_tool(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut ToolEconomyContext<'_>>,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            InvocationError::ContextNotActive { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // has_tool_invoke_capability
    // -----------------------------------------------------------------------

    #[test]
    fn has_tool_invoke_capability_returns_true_for_invoke_all() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        assert!(has_tool_invoke_capability(
            &role_state,
            "did:dht:z6MkCreator",
            "any-tool"
        ));
    }

    #[test]
    fn has_tool_invoke_capability_returns_false_without_capability() {
        let role_state =
            test_role_state_with_no_invoke_member("did:dht:z6MkCreator", "did:dht:z6MkMember");
        assert!(!has_tool_invoke_capability(
            &role_state,
            "did:dht:z6MkMember",
            "calculator"
        ));
    }

    #[test]
    fn has_tool_invoke_capability_with_specific_tool() {
        let mut role_state =
            test_role_state_with_no_invoke_member("did:dht:z6MkCreator", "did:dht:z6MkMember");
        // Add specific ToolInvoke capability.
        role_state
            .member_capabilities
            .get_mut("did:dht:z6MkMember")
            .unwrap()
            .insert(Capability::ToolInvoke("calculator".to_owned()));

        assert!(has_tool_invoke_capability(
            &role_state,
            "did:dht:z6MkMember",
            "calculator"
        ));
        // But not for a different tool.
        assert!(!has_tool_invoke_capability(
            &role_state,
            "did:dht:z6MkMember",
            "other-tool"
        ));
    }

    // -----------------------------------------------------------------------
    // invoke_tool: timeout is clamped to protocol maximum
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_tool_clamps_timeout_to_protocol_maximum() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        // Request a timeout larger than the protocol max.
        // The executor completes immediately, so the test verifies the function
        // does not error out due to an absurdly large timeout.
        let result = invoke_tool(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            Some(999_999), // Above MAX_TIMEOUT_MS
            add_executor,
            None::<&mut ToolEconomyContext<'_>>,
        )
        .await;

        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // InvocationError display messages
    // -----------------------------------------------------------------------

    #[test]
    fn invocation_error_display_messages() {
        let err = InvocationError::ContextNotActive {
            current_state: "Closing".to_owned(),
        };
        assert!(err.to_string().contains("Closing"));

        let err = InvocationError::InvokerNotAuthorized {
            did: "did:dht:test".into(),
            tool_id: "tool-1".to_owned(),
        };
        assert!(err.to_string().contains("did:dht:test"));
        assert!(err.to_string().contains("tool-1"));

        let err = InvocationError::ToolNotFound {
            tool_id: "missing".to_owned(),
        };
        assert!(err.to_string().contains("missing"));

        let err = InvocationError::Timeout { timeout_ms: 5000 };
        assert!(err.to_string().contains("5000"));

        let err = InvocationError::Cancelled;
        assert!(err.to_string().contains("cancelled"));
    }

    // -----------------------------------------------------------------------
    // validate_tool_invocation_ucan: rejects non-tool capability (#319)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_tool_invocation_ucan_rejects_non_tool_capability() {
        use crate::crypto::ucan::mint::{MintParams, mint_ucan};
        use scp_platform::testing::InMemoryKeyCustody;
        use scp_platform::traits::{KeyCustody, KeyType};
        use scp_protocol::crypto::ucan::validate::{
            DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, InMemoryDidResolver, InMemoryNonceTracker,
            InMemoryProofResolver, InMemoryRevocationChecker, ValidationContext,
        };

        // Set up issuer identity.
        let custody = InMemoryKeyCustody::new();
        let key_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&key_handle).await.unwrap();
        let pk_bytes: [u8; 32] = pubkey.as_bytes().try_into().unwrap();
        let issuer_did = format!("did:dht:z{}", zbase32::encode(pubkey.as_bytes()));

        // Mint a UCAN with messages:write capability (NOT tool_invoke).
        let caps = vec!["messages:write".to_owned()];
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };
        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Build validation context.
        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling: HashSet<String> = [
            "messages:write".to_owned(),
            "tool_invoke:calculator".to_owned(),
        ]
        .into_iter()
        .collect();

        let mut ctx = ValidationContext {
            did_resolver: &resolver,
            nonce_tracker: &mut nonce_tracker,
            revocation_checker: &revocation_checker,
            proof_resolver: &proof_resolver,
            ceiling: &ceiling,
            context_creator_did: &issuer_did,
            presenting_agent_did: "did:dht:z6MkMember",
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            clock: &scp_primitives::SystemClock,
        };

        // validate_tool_invocation_ucan expects tool_invoke:calculator,
        // but the token only has messages:write — must be rejected.
        let result =
            validate_tool_invocation_ucan(&token.encoded, "ctx-test", "calculator", &mut ctx);

        assert!(
            result.is_err(),
            "UCAN with messages:write must be rejected for tool invocation"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, UcanError::CapabilityNotGranted(..)),
            "expected CapabilityNotGranted, got {err:?}"
        );
    }

    // budget_exceeded on tool invocation returns BudgetExceeded
    #[tokio::test]
    async fn budget_exceeded_tool_invoke() {
        use scp_protocol::economy::types::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};

        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: CurrencyCode::new([85, 83, 68, 0]),
                per_message: None,
                per_tool_invoke: Some(Amount::new(200)),
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec![],
            pricing_formula: None,
            payee: DID::from("did:key:payee"),
        };

        let invoker: DID = "did:key:invoker".into();
        let mut tracker = scp_protocol::economy::budget::MemberBudgetTracker::new();
        // Grant only 100 budget but tool costs 200.
        tracker.grant(&invoker, Amount::new(100));

        let result = super::check_tool_economy(Some(&policy), &mut tracker, &invoker);
        assert!(
            matches!(result, Err(super::InvocationError::BudgetExceeded { .. })),
            "should return BudgetExceeded when budget is insufficient, got: {result:?}"
        );
    }
}
