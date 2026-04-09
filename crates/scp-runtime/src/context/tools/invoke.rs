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
    /// Spending UCAN for spending-capability check (§19.5). `None` if no
    /// spending UCAN presented. The action capability side of AND-composition
    /// is verified UPSTREAM at the `member_has_capability` gate — see the
    /// `ToolInvoke` / `ToolInvokeAll` check earlier in `invoke_tool`.
    pub spending_ucan: Option<&'a UcanToken>,
    /// Context ID for bookkeeping.
    pub context_id: &'a str,
    /// Current timestamp (seconds since epoch).
    pub now: u64,
    /// Event log entries for consequence evaluation.
    pub events: &'a [scp_event_log::Event],
    /// Participation cache for proposer eligibility evaluation.
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
    /// Per-DID velocity tracker (spec §19.4) for tool-invoke escalation.
    /// `None` skips per-DID escalation; pricing baseline (if any) still
    /// applies through the policy formula or `message_pricing.base_cost`.
    pub velocity_tracker: Option<&'a scp_protocol::economy::antispam::SenderVelocityTracker>,
    /// Per-DID message pricing config (spec §19.7). Carries base cost,
    /// escalation thresholds, and floor/cap. When `Some`, tool invocations
    /// participate in the same per-DID anti-spam regime as message sends.
    pub message_pricing: Option<&'a scp_protocol::economy::antispam::ContextMessagePricingConfig>,
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
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Full economy + escrow lifecycle
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
    // 1-4. Validate context state, capability, tool registration, and input
    // schema BEFORE deducting budget. The helper
    // `invoke_tool_execute_and_validate` runs the same checks again after the
    // economy pre-check — this is intentional redundancy so direct callers
    // get the pre-budget early bail path while the manager wrapper can share
    // the helper directly without replicating the economy flow.
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

    // 4a. Economy pre-check (#1537). Strategy B: `economy_pre_check` is pure
    // compute — it does NOT deduct budget. We immediately call `record_spend`
    // here so the behavior visible to direct callers of `invoke_tool` is
    // unchanged (budget is still debited before the executor runs). The
    // manager wrapper `ContextManager::invoke_tool_with_economy` bypasses
    // this code path entirely so it can snapshot state under its own lock.
    let action_cost = match economy.as_deref_mut() {
        Some(econ) => {
            let cost = economy_pre_check(econ, invoker_did)?;
            if cost.0 > 0 {
                econ.budget_tracker
                    .record_spend(invoker_did, cost)
                    .map_err(|_| InvocationError::BudgetExceeded {
                        did: invoker_did.to_string(),
                        cost: cost.0,
                        remaining: econ.budget_tracker.remaining(invoker_did).0,
                    })?;
            }
            Some(cost)
        }
        None => None,
    };

    // 4b. Payment escrow (#1537, #1596): authorize (escrow hold) BEFORE tool execution.
    let escrow_parts = extract_escrow_parts(&economy);
    let mut escrow = if let Some((adapter, policy, metrics, ctx_id)) = &escrow_parts {
        match authorize_tool_payment(adapter.as_ref(), policy, ctx_id, invoker_did, metrics).await {
            Ok(prepared) => prepared,
            Err(auth_err) => {
                void_escrow_and_rollback(
                    None,
                    escrow_parts.as_ref(),
                    action_cost,
                    &mut economy,
                    invoker_did,
                )
                .await;
                return Err(auth_err);
            }
        }
    } else {
        None
    };

    // 5-6. Execute the tool with timeout and validate the output. Delegates
    // to the shared `invoke_tool_execute_and_validate` helper so the manager
    // wrapper can share the exact same execution path.
    let outcome = match invoke_tool_execute_and_validate(
        context,
        registry,
        role_state,
        tool_id,
        input,
        invoker_did,
        timeout_ms,
        executor,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(err) => {
            void_escrow_and_rollback(
                escrow.as_ref(),
                escrow_parts.as_ref(),
                action_cost,
                &mut economy,
                invoker_did,
            )
            .await;
            return Err(err);
        }
    };
    let InvokeExecuteOutcome {
        output,
        input_hash,
        output_hash,
        execution_time_ms,
    } = outcome;

    // 6a. Post-invocation bookkeeping (#1530, #1531) — participation +
    // consequence evaluation.
    let triggered = economy
        .as_mut()
        .map(|econ| economy_post_check(econ, invoker_did))
        .unwrap_or_default();

    // 6b. Complete (capture) the escrowed payment after successful execution.
    let payment_receipt = finalize_tool_escrow(
        escrow.take(),
        escrow_parts.as_ref(),
        action_cost,
        &mut economy,
        invoker_did,
    )
    .await?;

    // 7-8. Build event + return (#1596: receipt returned to caller).
    let event = build_tool_event(
        tool_id,
        invoker_did,
        execution_time_ms,
        input_hash,
        output_hash,
        action_cost,
    );
    Ok((output, event, triggered, payment_receipt))
}

/// Outcome of [`invoke_tool_execute_and_validate`] — the pure-execution half
/// of tool invocation shared between direct callers and the
/// [`ContextManager::invoke_tool_with_economy`](crate::context::ContextManager::invoke_tool_with_economy)
/// wrapper. Captures everything needed to build a [`ToolInvokedEvent`]
/// without re-running the executor or rehashing the payloads.
#[derive(Debug)]
pub(crate) struct InvokeExecuteOutcome {
    /// The tool output value (already schema-validated).
    pub output: serde_json::Value,
    /// SHA-256 hash of the input JSON (hex-encoded). Computed from the input
    /// the executor actually saw, before execution.
    pub input_hash: String,
    /// SHA-256 hash of the output JSON (hex-encoded). Computed after the
    /// executor returned and before output-schema validation so the hash
    /// reflects what the executor produced verbatim.
    pub output_hash: String,
    /// Wall-clock execution time in milliseconds, from just before the
    /// executor was dispatched to just after output-schema validation
    /// succeeded.
    pub execution_time_ms: u64,
}

/// Runs steps 1-6 of tool invocation without any economy state.
///
/// This helper is the off-lock execution half of tool invocation. It
/// performs: context-state check, capability check, tool lookup, input
/// schema validation, executor dispatch under a bounded timeout, and
/// output schema validation. It deliberately takes NO economy context
/// and touches no governance state so that
/// [`ContextManager::invoke_tool_with_economy`](crate::context::ContextManager::invoke_tool_with_economy)
/// can call it with the `contexts` mutex dropped.
///
/// The free [`invoke_tool`] function also delegates to this helper after
/// running economy pre-check / escrow authorization, so the execution
/// path is shared between the two entry points.
///
/// # Errors
///
/// Returns [`InvocationError`] on state, capability, schema validation,
/// timeout, or executor failure. Cancellation is not supported by this
/// variant — see the inline timeout-plus-select! path in
/// [`invoke_tool_with_cancellation`] instead.
#[allow(clippy::too_many_arguments)] // 8 parameters mirror `invoke_tool`; lower bound imposed by the execution contract.
pub(crate) async fn invoke_tool_execute_and_validate<F, Fut>(
    context: &ContextHandle,
    registry: &ToolRegistry,
    role_state: &ContextRoleState,
    tool_id: &ToolId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: F,
) -> Result<InvokeExecuteOutcome, InvocationError>
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

    // 4a. Compute the input hash up-front from the value the executor will
    // see. Doing this before execution lets the hash be recorded even if the
    // executor mutates the input object (serde_json::Value is a value type,
    // but this also protects against any future change to `F` that might
    // take the input by reference and mutate it).
    let input_hash = sha256_json(&input);

    // 5. Execute the tool with timeout.
    let effective_timeout = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS).min(MAX_TIMEOUT_MS);
    let timeout_duration = Duration::from_millis(u64::from(effective_timeout));
    let execution_result = tokio::time::timeout(timeout_duration, executor(input)).await;
    let output = match execution_result {
        Ok(Ok(output)) => output,
        Ok(Err(exec_err)) => {
            return Err(InvocationError::ExecutionFailed { message: exec_err });
        }
        Err(_elapsed) => {
            return Err(InvocationError::Timeout {
                timeout_ms: effective_timeout,
            });
        }
    };

    // 6. Validate output against the tool's output schema.
    validate_value_against_schema(&output, &registration.schema.output_schema)
        .map_err(|msg| InvocationError::OutputValidationFailed { message: msg })?;

    let output_hash = sha256_json(&output);
    let execution_time_ms = elapsed_ms(start);

    Ok(InvokeExecuteOutcome {
        output,
        input_hash,
        output_hash,
        execution_time_ms,
    })
}

/// Runs economy pre-checks (pure compute — no state mutation).
///
/// Strategy B: this function is a PURE compute that returns the owned
/// evaluated cost. It does NOT mutate `budget_tracker`. Callers are
/// responsible for explicitly calling `budget_tracker.record_spend` after
/// this function returns so that budget mutation is visible at the call
/// site. Separating "compute cost" from "deduct budget" lets the
/// `ContextManager::invoke_tool_with_economy` wrapper snapshot state in
/// Phase 1 under the locked contexts mutex, drop the lock, run the
/// executor off-lock, and commit/rollback in Phase 3.
///
/// Uses real observable metrics from `ToolEconomyContext` (not zero metrics).
/// Evaluates cost, applies per-DID escalation, checks spending UCAN
/// AND-composition (§19.5), and checks `has_budget` for the invoker.
///
/// Returns the evaluated action cost for inclusion in the `ToolInvokedEvent`.
pub(crate) fn economy_pre_check<S: BuildHasher>(
    economy: &ToolEconomyContext<'_, S>,
    invoker_did: &DID,
) -> Result<scp_protocol::economy::types::Amount, InvocationError> {
    // Step 1: derive a base cost. Policy formula takes precedence; otherwise
    // fall back to the per-DID pricing baseline. With neither, the action is
    // free.
    let base_cost = if let Some(policy) = economy.economic_policy {
        scp_protocol::economy::policy::evaluate_cost(
            policy,
            &scp_protocol::economy::types::PaidActionType::ToolInvoke,
            &economy.metrics,
        )
        .ok_or_else(|| InvocationError::BudgetExceeded {
            did: invoker_did.to_string(),
            cost: u64::MAX,
            remaining: 0,
        })?
    } else if let Some(pricing) = economy.message_pricing {
        pricing.base_cost
    } else {
        return Ok(scp_protocol::economy::types::Amount::new(0));
    };

    // Step 2: apply per-DID escalation (§19.7) when both the velocity tracker
    // and the pricing config are wired through. This mirrors `enforce_economy`
    // for messages and joins.
    let cost = match (economy.velocity_tracker, economy.message_pricing) {
        (Some(tracker), Some(pricing)) => tracker.compute_escalated_cost(
            invoker_did,
            economy.now,
            base_cost,
            &pricing.escalation,
            pricing.floor,
            pricing.cap,
        ),
        _ => base_cost,
    };

    if cost.0 == 0 {
        return Ok(cost);
    }

    // Spending UCAN check (§19.5): paid actions require a spending UCAN.
    // The action capability was already verified at step 2 via the
    // `ToolInvoke` / `ToolInvokeAll` `member_has_capability` check — that
    // is the action side of AND-composition (see spec §19.5 layer split).
    check_tool_spending_capability(cost, economy.spending_ucan)?;

    // Budget check — no auto-grant. Budget must be explicitly approved via
    // ApproveSpend governance action. We deliberately do NOT call
    // `record_spend` here; the caller performs the deduction after this
    // function returns so the mutation point is visible and Strategy B
    // keeps this function pure.
    if !economy.budget_tracker.has_budget(invoker_did) {
        return Err(InvocationError::BudgetExceeded {
            did: invoker_did.to_string(),
            cost: cost.0,
            remaining: 0,
        });
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
///
/// Accepts pre-computed hashes and elapsed time so the event constructor
/// is a pure data-assembly step that both direct callers and the
/// `ContextManager::invoke_tool_with_economy` wrapper can share.
pub(crate) fn build_tool_event(
    tool_id: &ToolId,
    invoker_did: &DID,
    execution_time_ms: u64,
    input_hash: String,
    output_hash: String,
    cost: Option<scp_protocol::economy::types::Amount>,
) -> ToolInvokedEvent {
    ToolInvokedEvent {
        request_id: uuid::Uuid::new_v4().to_string(),
        tool_id: tool_id.to_owned(),
        invoker_did: invoker_did.clone(),
        status: ToolStatus::Success,
        execution_time_ms,
        input_hash,
        output_hash: Some(output_hash),
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
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // H6 escrow rollback on output validation adds lines; splitting would fragment the escrow lifecycle.
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

    // 4a. Economy pre-check (#1537). Strategy B: `economy_pre_check` is pure
    // compute — it does NOT deduct budget. Callers record the spend
    // explicitly so the mutation point is visible. See
    // `invoke_tool` for the matching comment on the non-cancellable path.
    let action_cost = match economy.as_deref_mut() {
        Some(econ) => {
            let cost = economy_pre_check(econ, invoker_did)?;
            if cost.0 > 0 {
                econ.budget_tracker
                    .record_spend(invoker_did, cost)
                    .map_err(|_| InvocationError::BudgetExceeded {
                        did: invoker_did.to_string(),
                        cost: cost.0,
                        remaining: econ.budget_tracker.remaining(invoker_did).0,
                    })?;
            }
            Some(cost)
        }
        None => None,
    };

    // 4b. Payment escrow (#1537, #1596): authorize (escrow hold) BEFORE tool execution.
    let escrow_parts = extract_escrow_parts(&economy);
    let mut escrow = if let Some((adapter, policy, metrics, ctx_id)) = &escrow_parts {
        match authorize_tool_payment(adapter.as_ref(), policy, ctx_id, invoker_did, metrics).await {
            Ok(prepared) => prepared,
            Err(auth_err) => {
                void_escrow_and_rollback(
                    None,
                    escrow_parts.as_ref(),
                    action_cost,
                    &mut economy,
                    invoker_did,
                )
                .await;
                return Err(auth_err);
            }
        }
    } else {
        None
    };

    // 4c. Compute the input hash from the value the executor will see so
    // the resulting `ToolInvokedEvent` records it verbatim even though we
    // have to clone the input for the cancellation path.
    let input_hash = sha256_json(&input);

    // 5. Execute with timeout and cancellation. The cancellation variant
    // keeps its own `tokio::select!` body because composing `tokio::select!`
    // across a helper boundary cannot carry the pinned `&mut` futures out
    // of scope — the cancellation-free path delegates to
    // `invoke_tool_execute_and_validate` instead.
    let effective_timeout = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS).min(MAX_TIMEOUT_MS);
    let timeout_duration = Duration::from_millis(u64::from(effective_timeout));
    let exec_fut = executor(input);
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
    let exec_result = match execution_result {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(msg)) if msg == "cancelled" => Err(InvocationError::Cancelled),
        Ok(Err(exec_err)) => Err(InvocationError::ExecutionFailed { message: exec_err }),
        Err(_elapsed) => Err(InvocationError::Timeout {
            timeout_ms: effective_timeout,
        }),
    };
    let output = match exec_result {
        Ok(output) => output,
        Err(err) => {
            void_escrow_and_rollback(
                escrow.as_ref(),
                escrow_parts.as_ref(),
                action_cost,
                &mut economy,
                invoker_did,
            )
            .await;
            return Err(err);
        }
    };

    // 6. Validate output + post-invocation bookkeeping.
    // H6: on output validation failure, void escrow and rollback budget
    // before returning.
    if let Err(msg) = validate_value_against_schema(&output, &registration.schema.output_schema) {
        void_escrow_and_rollback(
            escrow.as_ref(),
            escrow_parts.as_ref(),
            action_cost,
            &mut economy,
            invoker_did,
        )
        .await;
        return Err(InvocationError::OutputValidationFailed { message: msg });
    }
    let output_hash = sha256_json(&output);
    let execution_time_ms = elapsed_ms(start);
    let triggered = economy
        .as_mut()
        .map(|econ| economy_post_check(econ, invoker_did))
        .unwrap_or_default();

    // 6b. Complete (capture) the escrowed payment after successful execution.
    let payment_receipt = finalize_tool_escrow(
        escrow.take(),
        escrow_parts.as_ref(),
        action_cost,
        &mut economy,
        invoker_did,
    )
    .await?;

    // 7. Build event + return (#1596: receipt returned to caller).
    let event = build_tool_event(
        tool_id,
        invoker_did,
        execution_time_ms,
        input_hash,
        output_hash,
        action_cost,
    );
    Ok((output, event, triggered, payment_receipt))
}

/// Post-invocation bookkeeping: participation record update and consequence evaluation.
///
/// Called after a successful tool invocation to update governance state.
/// `compute_participation_record` refreshes the cache for proposer eligibility
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

/// Validates the spending side of AND-composition for paid tool invocations
/// (spec §19.5).
///
/// Per spec §19.5, paid actions require BOTH an action capability AND a
/// spending UCAN. The action capability is verified UPSTREAM at the
/// `ToolInvoke` / `ToolInvokeAll` `member_has_capability` gate (see
/// `invoke_tool`). This function verifies the spending side only.
///
/// # Errors
///
/// Returns [`InvocationError::ExecutionFailed`] if the spending UCAN is
/// missing for a paid action or if the spending capability is malformed.
pub fn check_tool_spending_capability(
    action_cost: scp_protocol::economy::types::Amount,
    spending_ucan: Option<&UcanToken>,
) -> Result<(), InvocationError> {
    // Convert economy Amount to UCAN spending Amount (both are u64 wrappers).
    let ucan_amount = scp_protocol::crypto::ucan::spending::Amount(action_cost.0);
    scp_protocol::crypto::ucan::spending::check_spending_capability(
        spending_ucan,
        ucan_amount,
        "tool:invoke",
    )
    .map_err(|e| InvocationError::ExecutionFailed {
        message: format!("UCAN spending capability check failed: {e}"),
    })
}

/// Extracts adapter/policy/metrics from economy context for escrow flow.
///
/// Returns owned copies to avoid holding a borrow of `economy` across the
/// mutable post-check. Returns `None` when no adapter or policy is configured.
fn extract_escrow_parts<S: BuildHasher>(
    economy: &Option<&mut ToolEconomyContext<'_, S>>,
) -> Option<EscrowParts> {
    let econ = economy.as_ref()?;
    let adapter = econ.payment_adapter.as_ref().map(std::sync::Arc::clone)?;
    let policy = econ.economic_policy?.clone();
    let metrics = econ.metrics.clone();
    let context_id = econ.context_id.to_owned();
    Some((adapter, policy, metrics, context_id))
}

/// Completes the escrow payment after successful tool execution, or rolls back
/// the budget on capture failure.
///
/// Returns the payment receipt (if any). On capture failure, rolls back budget
/// and returns the error.
async fn finalize_tool_escrow<S: BuildHasher>(
    escrow: Option<crate::economy::integration::PreparedAction>,
    escrow_parts: Option<&EscrowParts>,
    action_cost: Option<scp_protocol::economy::types::Amount>,
    economy: &mut Option<&mut ToolEconomyContext<'_, S>>,
    invoker_did: &DID,
) -> Result<Option<crate::economy::adapter::PaymentReceipt>, InvocationError> {
    if let (Some(prepared), Some((adapter, policy, metrics, _))) = (escrow, escrow_parts) {
        match complete_tool_payment(adapter.as_ref(), Some(policy), &prepared, metrics).await {
            Ok(receipt) => Ok(receipt),
            Err(capture_err) => {
                // Budget rollback only — escrow is already consumed by the capture attempt.
                // Use reverse_spend (not grant) to avoid inflating limits (#1606 M1).
                if let Some(cost) = action_cost
                    && let Some(econ) = economy
                {
                    econ.budget_tracker.reverse_spend(invoker_did, cost);
                }
                Err(capture_err)
            }
        }
    } else {
        Ok(None)
    }
}

/// Extracted escrow context: adapter, policy, metrics, context ID.
type EscrowParts = (
    std::sync::Arc<dyn crate::economy::adapter::PaymentAdapterDyn>,
    scp_protocol::economy::types::EconomicPolicy,
    scp_protocol::economy::policy::ObservableMetrics,
    String,
);

/// Voids the payment escrow and rolls back budget on tool failure.
///
/// Combines the void + rollback pattern that appears in every failure branch
/// of `invoke_tool` and `invoke_tool_with_cancellation`.
async fn void_escrow_and_rollback<S: BuildHasher>(
    escrow: Option<&crate::economy::integration::PreparedAction>,
    escrow_parts: Option<&EscrowParts>,
    action_cost: Option<scp_protocol::economy::types::Amount>,
    economy: &mut Option<&mut ToolEconomyContext<'_, S>>,
    invoker_did: &DID,
) {
    if let (Some(prepared), Some((adapter, _, _, _))) = (escrow, escrow_parts) {
        void_tool_escrow(adapter.as_ref(), prepared).await;
    }
    if let Some(cost) = action_cost
        && let Some(econ) = economy
    {
        econ.budget_tracker.reverse_spend(invoker_did, cost);
    }
}

// ---------------------------------------------------------------------------
// Escrow payment flow for tool invocations (#1537)
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

/// Authorizes a tool payment (escrow step 1).
///
/// Creates an escrow hold via `prepare_paid_action`. Returns the bridge
/// and prepared action for later completion or voiding. Returns `None`
/// when cost is zero or no payment is needed.
///
/// Called BEFORE tool execution. On success, the caller must eventually call
/// `complete_tool_payment` or `void_tool_escrow`.
pub(crate) async fn authorize_tool_payment(
    adapter: &dyn crate::economy::adapter::PaymentAdapterDyn,
    policy: &scp_protocol::economy::types::EconomicPolicy,
    context_id: &str,
    invoker_did: &DID,
    metrics: &scp_protocol::economy::policy::ObservableMetrics,
) -> Result<Option<crate::economy::integration::PreparedAction>, InvocationError> {
    let cost = scp_protocol::economy::policy::evaluate_cost(
        policy,
        &scp_protocol::economy::types::PaidActionType::ToolInvoke,
        metrics,
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

    let prepared = crate::economy::integration::prepare_paid_action(
        &bridge,
        Some(policy),
        scp_protocol::economy::types::PaidActionType::ToolInvoke,
        invoker_did,
        Some(context_id.to_owned()),
        metrics,
        metadata,
        Vec::new(),
    )
    .await
    .map_err(|_| InvocationError::BudgetExceeded {
        did: invoker_did.to_string(),
        cost: cost.0,
        remaining: 0, // Exact remaining not available here; adapter rejected the hold.
    })?;

    Ok(Some(prepared))
}

/// Completes a tool payment (escrow step 2: capture).
///
/// Called AFTER successful tool execution. Captures the escrowed payment
/// and returns the receipt.
pub(crate) async fn complete_tool_payment(
    adapter: &dyn crate::economy::adapter::PaymentAdapterDyn,
    policy: Option<&scp_protocol::economy::types::EconomicPolicy>,
    prepared: &crate::economy::integration::PreparedAction,
    metrics: &scp_protocol::economy::policy::ObservableMetrics,
) -> Result<Option<crate::economy::adapter::PaymentReceipt>, InvocationError> {
    let bridge = ToolPaymentBridge(adapter);
    let processed = crate::economy::integration::process_paid_action(
        &bridge,
        policy,
        &prepared.envelope,
        metrics,
        |payload| async move { Ok(payload) },
    )
    .await
    .map_err(|_| InvocationError::ExecutionFailed {
        message: "payment capture failed after successful tool execution".to_owned(),
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

/// Voids a tool payment escrow on failure.
///
/// Called when tool execution fails (error, timeout, cancellation) to
/// release the escrow hold. Best-effort — logs but does not propagate
/// void failures.
pub(crate) async fn void_tool_escrow(
    adapter: &dyn crate::economy::adapter::PaymentAdapterDyn,
    prepared: &crate::economy::integration::PreparedAction,
) {
    if let Some(ref authorization) = prepared.envelope.authorization {
        let bridge = ToolPaymentBridge(adapter);
        if let Err(e) = crate::economy::adapter::PaymentAdapter::void(&bridge, authorization).await
        {
            tracing::warn!("failed to void tool payment escrow: {e}");
        }
    }
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

        // Budget enforcement is now inline in economy_pre_check via invoke_tool.
        // Test it through invoke_tool with a ToolEconomyContext.
        let context = active_context().await;
        let role_state = test_role_state(invoker.as_ref());
        let registry = setup_registry_with_tool(&role_state, invoker.as_ref());
        let metrics = scp_protocol::economy::policy::ObservableMetrics {
            context_message_rate: 0,
            member_count: 0,
            relay_queue_depth: 0,
            time_of_day: 0,
            sender_velocity: 0,
            storage_usage: 0,
        };
        let mut participation: std::collections::HashMap<
            String,
            scp_protocol::trust::participation::ParticipationRecord,
        > = std::collections::HashMap::new();
        // Provide a spending UCAN so the AND-composition check passes;
        // the budget check (the actual test target) runs after.
        let spending_ucan = {
            use scp_protocol::crypto::ucan::spending::{
                Amount as SpendingAmount, CurrencyCode as SpendingCurrency, SpendingCapability,
            };
            let cap = SpendingCapability {
                max_per_action: SpendingAmount(u64::MAX),
                max_total: SpendingAmount(u64::MAX),
                currency: SpendingCurrency([85, 83, 68, 0]),
                time_window: std::time::Duration::from_secs(86400),
                allowed_adapters: vec![],
            };
            let mut fct = serde_json::Map::new();
            fct.insert(
                "spending_capability".to_owned(),
                cap.to_fact_value().unwrap(),
            );
            scp_protocol::crypto::ucan::UcanToken {
                header: scp_protocol::crypto::ucan::UcanHeader::new(),
                payload: scp_protocol::crypto::ucan::UcanPayload {
                    iss: "did:key:test".to_owned(),
                    aud: "did:key:aud".to_owned(),
                    exp: u64::MAX,
                    nbf: None,
                    nnc: "test-nonce".to_owned(),
                    att: vec![],
                    prf: vec![],
                    fct: Some(serde_json::Value::Object(fct)),
                },
                signature: vec![0u8; 64],
                encoded: String::new(),
            }
        };
        let mut economy = super::ToolEconomyContext {
            economic_policy: Some(&policy),
            budget_tracker: &mut tracker,
            spending_ucan: Some(&spending_ucan),
            context_id: "ctx-invoke-test",
            now: 0,
            events: &[],
            participation_cache: &mut participation,
            consequence_rules: &[],
            payment_adapter: None,
            metrics,
            velocity_tracker: None,
            message_pricing: None,
        };

        let result = super::invoke_tool(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &invoker,
            None,
            add_executor,
            Some(&mut economy),
        )
        .await;
        assert!(
            matches!(result, Err(super::InvocationError::BudgetExceeded { .. })),
            "should return BudgetExceeded when budget is insufficient, got: {result:?}"
        );
    }
}
