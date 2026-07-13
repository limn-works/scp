//! Outlet invocation with full execution lifecycle.
//!
//! Implements [`invoke_outlet`]: the primary entry point for executing a
//! registered outlet within an SCP context. Handles context state validation,
//! UCAN capability checking, input/output schema validation, timeout
//! enforcement, cancellation, error propagation, and event log recording.
//!
//! Outlet execution errors are surfaced as [`InvocationError::ExecutionFailed`]
//! carrying the executor's message. Schema validation failures are caught by
//! the SDK (this module), not by the outlet itself.
//!
//! See ADR-010 in `.docs/adrs/phase-2.md` for the full design.

use std::future::Future;
use std::hash::BuildHasher;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::context::ContextHandle;
use scp_did::DID;
use scp_protocol::context::ContextState;
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::lifecycle::{
    DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS, OutletInvokedEvent, OutletStatus, sha256_json,
};
use scp_protocol::context::outlets::registry::OutletRegistry;
use scp_protocol::context::outlets::schema::validate_value_against_schema;
use scp_protocol::context::outlets::stream::{
    ChunkPayload, OutletStreamChunk, RequestId, StreamTerminalStatus,
};
use scp_protocol::context::roles::ContextRoleState;
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

/// Errors produced by [`invoke_outlet`].
///
/// These are protocol-level errors that prevent the invocation from being
/// dispatched. Outlet execution errors are surfaced as the
/// [`ExecutionFailed`](InvocationError::ExecutionFailed) variant instead.
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
        "invoker \"{did}\" does not have OutletCall(\"{outlet_id}\") or OutletCallAll capability"
    )]
    InvokerNotAuthorized {
        /// The DID that attempted invocation.
        did: String,
        /// The outlet they tried to invoke.
        outlet_id: String,
    },

    /// The outlet was not found in the registry.
    #[error("outlet not found: \"{outlet_id}\"")]
    OutletNotFound {
        /// The outlet ID that was not found.
        outlet_id: String,
    },

    /// Input validation failed against the outlet's input schema.
    #[error("input validation failed: {message}")]
    InputValidationFailed {
        /// Description of the validation failure.
        message: String,
    },

    /// Output validation failed against the outlet's output schema.
    #[error("output validation failed: {message}")]
    OutputValidationFailed {
        /// Description of the validation failure.
        message: String,
    },

    /// The outlet execution timed out.
    #[error("outlet execution timed out after {timeout_ms}ms")]
    Timeout {
        /// The timeout that was exceeded.
        timeout_ms: u32,
    },

    /// The outlet execution was cancelled.
    #[error("outlet execution was cancelled")]
    Cancelled,

    /// The outlet execution failed.
    #[error("outlet execution failed: {message}")]
    ExecutionFailed {
        /// Description of the execution failure.
        message: String,
    },

    /// The invoker's spending budget has been exceeded (§19.5, ADR-033).
    ///
    /// Returned when the context has an economic policy with a per-outlet-invoke
    /// cost and the invoker's cumulative spending would exceed their
    /// governance-approved budget.
    ///
    /// Error code: `SCP-PERM-3030`.
    #[error("budget exceeded for invoker \"{did}\": cost {cost}, remaining {remaining}")]
    BudgetExceeded {
        /// The DID that attempted invocation.
        did: String,
        /// The cost of the outlet invocation.
        cost: u64,
        /// The remaining budget for the invoker.
        remaining: u64,
    },

    /// A §7.3.8 invocation caveat rejected the call — either a synchronous
    /// local check ([`InvocationCaveats::check_invocation_local`](scp_protocol::trust::caveats::InvocationCaveats::check_invocation_local):
    /// `input_schema` / `amount_max_per_call` / `allowed_adapters` /
    /// `allowed_target_dids`) or a counter-bearing cap
    /// ([`CaveatCounters::try_consume`](crate::trust::caveat_counters::CaveatCounters::try_consume):
    /// `max_calls` / `amount_max_cumulative` / `rate_window`).
    ///
    /// Every variant maps to the Authorization-class code
    /// (`SCP-OUTLET-6110`); `slug` disambiguates which caveat rule fired in the
    /// wire envelope (§5.4.4 / §7.3.8).
    #[error("caveat violation [{slug}]: {message}")]
    CaveatViolation {
        /// The §5.4.4 / §7.3.8 slug identifying the caveat rule that fired.
        slug: String,
        /// Human-readable diagnostic for the SDK error envelope.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Economy context for outlet invocation
// ---------------------------------------------------------------------------

/// Optional economy parameters for outlet invocation.
///
/// When provided, `invoke_outlet` enforces budget checks before execution
/// and performs post-invocation bookkeeping (participation record update,
/// consequence rule evaluation). Pass `None` when economy is not configured
/// for the context.
pub struct OutletEconomyContext<'a, S: BuildHasher = std::hash::RandomState> {
    /// The context's economic policy (from `PerContextState.governance.economic_policy`).
    pub economic_policy: Option<&'a scp_protocol::economy::types::EconomicPolicy>,
    /// Mutable reference to the invoker's budget tracker.
    pub budget_tracker: &'a mut scp_protocol::economy::budget::MemberBudgetTracker,
    /// Spending UCAN for spending-capability check (§19.5). `None` if no
    /// spending UCAN presented. The action capability side of AND-composition
    /// is verified UPSTREAM at the `member_has_capability` gate — see the
    /// `OutletCall` / `OutletCallAll` check earlier in `invoke_outlet`.
    pub spending_ucan: Option<&'a UcanToken>,
    /// Context ID for bookkeeping.
    pub context_id: &'a str,
    /// Current timestamp (seconds since epoch).
    pub now: u64,
    /// Event log entries for consequence evaluation.
    pub events: &'a [scp_event_log::Event],
    /// Convergent window anchor (max timestamp of the Source-1 durable log,
    /// captured before the buffer merge). Anchors the evidence window for
    /// convergent-trigger consequence rules so the durable leaf is byte-identical
    /// across skewed members (§9.9.3); derived from the same call to
    /// `event_log_entries_for_consequences` that produced `events`.
    pub convergent_now: u64,
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
    /// When `Some`, `invoke_outlet` runs `prepare_paid_action` + `process_paid_action`
    /// before outlet execution. When `None`, only budget enforcement runs.
    pub payment_adapter: Option<std::sync::Arc<dyn crate::economy::adapter::PaymentAdapterDyn>>,
    /// Observable metrics for dynamic cost evaluation. Populated from
    /// `PerContextState` by the caller so that outlet economy uses real
    /// metrics instead of zeros.
    pub metrics: scp_protocol::economy::policy::ObservableMetrics,
    /// Per-DID velocity tracker (spec §19.4) for outlet-invoke escalation.
    /// `None` skips per-DID escalation; pricing baseline (if any) still
    /// applies through the policy formula or `message_pricing.base_cost`.
    pub velocity_tracker: Option<&'a scp_protocol::economy::antispam::SenderVelocityTracker>,
    /// Per-DID message pricing config (spec §19.7). Carries base cost,
    /// escalation thresholds, and floor/cap. When `Some`, outlet invocations
    /// participate in the same per-DID anti-spam regime as message sends.
    pub message_pricing: Option<&'a scp_protocol::economy::antispam::ContextMessagePricingConfig>,
}

// ---------------------------------------------------------------------------
// invoke_outlet
// ---------------------------------------------------------------------------

/// Invokes a outlet within a context, performing full lifecycle validation.
///
/// Execution flow:
/// 1. Validates context state is [`Active`](ContextState::Active).
/// 2. Validates invoker has
///    [`OutletCall(outlet_id)`](scp_protocol::context::roles::Capability::OutletCall)
///    or [`OutletCallAll`](scp_protocol::context::roles::Capability::OutletCallAll)
///    capability via UCAN.
/// 3. Looks up the outlet in the registry.
/// 4. Validates input against the outlet's input schema.
///    - 4a. Economy: checks budget and UCAN composition (if economy context provided).
/// 5. Calls the outlet implementation via the `executor` function.
/// 6. Validates output against the outlet's output schema.
///    - 6a. Post-invocation bookkeeping — participation + consequences.
/// 7. Builds a [`OutletInvokedEvent`] for the caller to append to the event log.
/// 8. Returns the outlet output and any triggered consequences.
///
/// # Timeout handling
///
/// The `timeout_ms` parameter specifies the maximum time to wait for the outlet
/// to complete. If the outlet does not complete within the timeout, a
/// [`InvocationError::Timeout`] is returned. The timeout is clamped to the
/// hard protocol maximum of [`MAX_TIMEOUT_MS`] (300,000ms / 5 minutes).
///
/// # Cancellation
///
/// Cancellation is handled externally via [`OutletCancel`](scp_protocol::context::outlets::lifecycle::OutletCancel)
/// messages. This function supports cancellation through a
/// `cancellation_token` future that resolves when cancellation is requested.
///
/// # Errors
///
/// Returns [`InvocationError`] on protocol-level validation failures,
/// budget exceeded, or UCAN composition failures.
///
/// See ADR-010 acceptance criterion 3 (`invoke_outlet`).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Full economy + escrow lifecycle
pub async fn invoke_outlet<F, Fut, S: BuildHasher>(
    context: &ContextHandle,
    registry: &OutletRegistry,
    role_state: &ContextRoleState,
    outlet_id: &OutletId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: F,
    mut economy: Option<&mut OutletEconomyContext<'_, S>>,
) -> Result<
    (
        serde_json::Value,
        OutletInvokedEvent,
        Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
        Option<crate::economy::adapter::PaymentReceipt>,
    ),
    InvocationError,
>
where
    F: FnOnce(serde_json::Value) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
{
    // 1-4. Validate context state, capability, outlet registration, and input
    // schema BEFORE deducting budget. The helper
    // `invoke_outlet_execute_and_validate` runs the same checks again after the
    // economy pre-check — this is intentional redundancy so direct callers
    // get the pre-budget early bail path while the manager wrapper can share
    // the helper directly without replicating the economy flow.
    let state = context.state();
    if state != ContextState::Active {
        return Err(InvocationError::ContextNotActive {
            current_state: state.to_string(),
        });
    }
    // SCP-OUT-014: resolve the registration first so the capability check can
    // branch on the outlet's registered kind — Query outlets require the
    // `outlet_query` stem, Action outlets require `outlet_call`.
    let registration = registry
        .get(outlet_id)
        .ok_or_else(|| InvocationError::OutletNotFound {
            outlet_id: outlet_id.to_owned(),
        })?;
    if !has_outlet_invocation_capability(role_state, invoker_did, outlet_id, registration.kind) {
        return Err(InvocationError::InvokerNotAuthorized {
            did: invoker_did.to_string(),
            outlet_id: outlet_id.to_owned(),
        });
    }
    validate_value_against_schema(&input, &registration.schema.input_schema)
        .map_err(|msg| InvocationError::InputValidationFailed { message: msg })?;

    // 4a. Economy pre-check (#1537). Strategy B: `economy_pre_check` is pure
    // compute — it does NOT deduct budget. We immediately call `record_spend`
    // here so the behavior visible to direct callers of `invoke_outlet` is
    // unchanged (budget is still debited before the executor runs). The
    // manager wrapper `ContextManager::invoke_outlet_with_economy` bypasses
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

    // 4b. Payment escrow (#1537, #1596): authorize (escrow hold) BEFORE outlet execution.
    let escrow_parts = extract_escrow_parts(&economy);
    let mut escrow = if let Some((adapter, policy, metrics, ctx_id)) = &escrow_parts {
        match authorize_outlet_payment(adapter.as_ref(), policy, ctx_id, invoker_did, metrics).await
        {
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

    // 5-6. Execute the outlet with timeout and validate the output. Delegates
    // to the shared `invoke_outlet_execute_and_validate` helper so the manager
    // wrapper can share the exact same execution path.
    let outcome = match invoke_outlet_execute_and_validate(
        context,
        registry,
        role_state,
        outlet_id,
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
    let payment_receipt = finalize_outlet_escrow(
        escrow.take(),
        escrow_parts.as_ref(),
        action_cost,
        &mut economy,
        invoker_did,
    )
    .await?;

    // 7-8. Build event + return (#1596: receipt returned to caller).
    let event = build_outlet_event(
        outlet_id,
        invoker_did,
        execution_time_ms,
        input_hash,
        output_hash,
        action_cost,
    );
    Ok((output, event, triggered, payment_receipt))
}

/// Outcome of [`invoke_outlet_execute_and_validate`] — the pure-execution half
/// of outlet invocation shared between direct callers and the
/// [`ContextManager::invoke_outlet_with_economy`](crate::context::ContextManager::invoke_outlet_with_economy)
/// wrapper. Captures everything needed to build a [`OutletInvokedEvent`]
/// without re-running the executor or rehashing the payloads.
#[derive(Debug)]
pub(crate) struct InvokeExecuteOutcome {
    /// The outlet output value (already schema-validated).
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

/// Runs steps 1-6 of outlet invocation without any economy state.
///
/// This helper is the off-lock execution half of outlet invocation. It
/// performs: context-state check, capability check, outlet lookup, input
/// schema validation, executor dispatch under a bounded timeout, and
/// output schema validation. It deliberately takes NO economy context
/// and touches no governance state so that
/// [`ContextManager::invoke_outlet_with_economy`](crate::context::ContextManager::invoke_outlet_with_economy)
/// can call it with the `contexts` mutex dropped.
///
/// The free [`invoke_outlet`] function also delegates to this helper after
/// running economy pre-check / escrow authorization, so the execution
/// path is shared between the two entry points.
///
/// # Errors
///
/// Returns [`InvocationError`] on state, capability, schema validation,
/// timeout, or executor failure. Cancellation is not supported by this
/// variant — see the inline timeout-plus-select! path in
/// [`invoke_outlet_with_cancellation`] instead.
#[allow(clippy::too_many_arguments)] // 8 parameters mirror `invoke_outlet`; lower bound imposed by the execution contract.
pub(crate) async fn invoke_outlet_execute_and_validate<F, Fut>(
    context: &ContextHandle,
    registry: &OutletRegistry,
    role_state: &ContextRoleState,
    outlet_id: &OutletId,
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
    let state = context.state();
    if state != ContextState::Active {
        return Err(InvocationError::ContextNotActive {
            current_state: state.to_string(),
        });
    }

    // 2. Look up the outlet in the registry first, so the capability check can
    //    branch on the outlet's registered kind (SCP-OUT-014).
    let registration = registry
        .get(outlet_id)
        .ok_or_else(|| InvocationError::OutletNotFound {
            outlet_id: outlet_id.to_owned(),
        })?;

    // 3. Validate invoker holds the kind-appropriate split capability —
    //    OutletQuery(outlet_id)/OutletQueryAll for Query outlets,
    //    OutletCall(outlet_id)/OutletCallAll for Action outlets (§5.4.2).
    if !has_outlet_invocation_capability(role_state, invoker_did, outlet_id, registration.kind) {
        return Err(InvocationError::InvokerNotAuthorized {
            did: invoker_did.to_string(),
            outlet_id: outlet_id.to_owned(),
        });
    }

    // 4. Validate input against the outlet's input schema.
    validate_value_against_schema(&input, &registration.schema.input_schema)
        .map_err(|msg| InvocationError::InputValidationFailed { message: msg })?;

    // 4a. Compute the input hash up-front from the value the executor will
    // see. Doing this before execution lets the hash be recorded even if the
    // executor mutates the input object (serde_json::Value is a value type,
    // but this also protects against any future change to `F` that might
    // take the input by reference and mutate it).
    let input_hash = sha256_json(&input);

    // 5. Execute the outlet with timeout.
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

    // 6. Validate output against the outlet's output schema.
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
/// `ContextManager::invoke_outlet_with_economy` wrapper snapshot state in
/// Phase 1 under the locked contexts mutex, drop the lock, run the
/// executor off-lock, and commit/rollback in Phase 3.
///
/// Uses real observable metrics from `OutletEconomyContext` (not zero metrics).
/// Evaluates cost, applies per-DID escalation, checks spending UCAN
/// AND-composition (§19.5), and checks `has_budget` for the invoker.
///
/// Returns the evaluated action cost for inclusion in the `OutletInvokedEvent`.
pub(crate) fn economy_pre_check<S: BuildHasher>(
    economy: &OutletEconomyContext<'_, S>,
    invoker_did: &DID,
) -> Result<scp_protocol::economy::types::Amount, InvocationError> {
    // Step 1: derive a base cost from the economic policy. Consistent with
    // `enforce_economy` (messages/joins): no economic policy → free action.
    // Anti-spam for free contexts is provided by the token-bucket hard rate
    // limit, which runs independently of the cost layer.
    let Some(policy) = economy.economic_policy else {
        return Ok(scp_protocol::economy::types::Amount::new(0));
    };
    let base_cost = scp_protocol::economy::policy::evaluate_cost(
        policy,
        &scp_protocol::economy::types::PaidActionType::OutletCall,
        &economy.metrics,
    )
    .ok_or_else(|| InvocationError::BudgetExceeded {
        did: invoker_did.to_string(),
        cost: u64::MAX,
        remaining: 0,
    })?;

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
    // `OutletCall` / `OutletCallAll` `member_has_capability` check — that
    // is the action side of AND-composition (see spec §19.5 layer split).
    check_outlet_spending_capability(cost, economy.spending_ucan)?;

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
    economy: &mut OutletEconomyContext<'_, S>,
    invoker_did: &DID,
) -> Vec<scp_protocol::trust::consequence::TriggeredConsequence> {
    post_outlet_invocation_bookkeeping(
        economy.events,
        invoker_did,
        economy.context_id,
        economy.now,
        economy.convergent_now,
        economy.participation_cache,
        economy.consequence_rules,
    )
}

/// Builds a [`OutletInvokedEvent`] from invocation metadata.
///
/// Accepts pre-computed hashes and elapsed time so the event constructor
/// is a pure data-assembly step that both direct callers and the
/// `ContextManager::invoke_outlet_with_economy` wrapper can share.
pub(crate) fn build_outlet_event(
    outlet_id: &OutletId,
    invoker_did: &DID,
    execution_time_ms: u64,
    input_hash: String,
    output_hash: String,
    cost: Option<scp_protocol::economy::types::Amount>,
) -> OutletInvokedEvent {
    OutletInvokedEvent {
        request_id: uuid::Uuid::new_v4().to_string(),
        outlet_id: outlet_id.to_owned(),
        invoker_did: invoker_did.clone(),
        status: OutletStatus::Success,
        execution_time_ms,
        input_hash,
        output_hash: Some(output_hash),
        cost,
        // Non-streaming invocation path: no chunks are produced, so the
        // streaming event fields take their degenerate/no-manifest defaults
        // — identical to the `#[serde(default …)]` values lifecycle.rs uses
        // for events that pre-date the streaming taxonomy. No streaming
        // behavior is introduced here; this is a shape reconcile only.
        stream_chunk_count: 0,
        chunks_billed: 0,
        stream_manifest_hash: [0u8; 32],
        stream_terminal_status: StreamTerminalStatus::Ok,
        audit_anomaly: None,
    }
}

/// Invokes a outlet with cancellation support.
///
/// Same as [`invoke_outlet`] but accepts a cancellation future. If the
/// cancellation future resolves before the outlet completes, the invocation
/// returns [`InvocationError::Cancelled`].
///
/// Cancellation is best-effort: if the outlet completes before the cancel
/// signal, the successful result is returned.
///
/// # Errors
///
/// Returns [`InvocationError`] on protocol-level validation failures,
/// timeout, cancellation, budget exceeded, or UCAN composition failures.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // H6 escrow rollback on output validation adds lines; splitting would fragment the escrow lifecycle.
pub async fn invoke_outlet_with_cancellation<F, Fut, C, CFut, S: BuildHasher>(
    context: &ContextHandle,
    registry: &OutletRegistry,
    role_state: &ContextRoleState,
    outlet_id: &OutletId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: F,
    cancellation: C,
    mut economy: Option<&mut OutletEconomyContext<'_, S>>,
) -> Result<
    (
        serde_json::Value,
        OutletInvokedEvent,
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

    // 1-4: Validate context, capability, outlet, schema (same as invoke_outlet).
    let state = context.state();
    if state != ContextState::Active {
        return Err(InvocationError::ContextNotActive {
            current_state: state.to_string(),
        });
    }
    // SCP-OUT-014: resolve the registration first so the capability check can
    // branch on the outlet's registered kind — Query outlets require the
    // `outlet_query` stem, Action outlets require `outlet_call`.
    let registration = registry
        .get(outlet_id)
        .ok_or_else(|| InvocationError::OutletNotFound {
            outlet_id: outlet_id.to_owned(),
        })?;
    if !has_outlet_invocation_capability(role_state, invoker_did, outlet_id, registration.kind) {
        return Err(InvocationError::InvokerNotAuthorized {
            did: invoker_did.to_string(),
            outlet_id: outlet_id.to_owned(),
        });
    }
    validate_value_against_schema(&input, &registration.schema.input_schema)
        .map_err(|msg| InvocationError::InputValidationFailed { message: msg })?;

    // 4a. Economy pre-check (#1537). Strategy B: `economy_pre_check` is pure
    // compute — it does NOT deduct budget. Callers record the spend
    // explicitly so the mutation point is visible. See
    // `invoke_outlet` for the matching comment on the non-cancellable path.
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

    // 4b. Payment escrow (#1537, #1596): authorize (escrow hold) BEFORE outlet execution.
    let escrow_parts = extract_escrow_parts(&economy);
    let mut escrow = if let Some((adapter, policy, metrics, ctx_id)) = &escrow_parts {
        match authorize_outlet_payment(adapter.as_ref(), policy, ctx_id, invoker_did, metrics).await
        {
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
    // the resulting `OutletInvokedEvent` records it verbatim even though we
    // have to clone the input for the cancellation path.
    let input_hash = sha256_json(&input);

    // 5. Execute with timeout and cancellation. The cancellation variant
    // keeps its own `tokio::select!` body because composing `tokio::select!`
    // across a helper boundary cannot carry the pinned `&mut` futures out
    // of scope — the cancellation-free path delegates to
    // `invoke_outlet_execute_and_validate` instead.
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
    let payment_receipt = finalize_outlet_escrow(
        escrow.take(),
        escrow_parts.as_ref(),
        action_cost,
        &mut economy,
        invoker_did,
    )
    .await?;

    // 7. Build event + return (#1596: receipt returned to caller).
    let event = build_outlet_event(
        outlet_id,
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
/// Called after a successful outlet invocation to update governance state.
/// `compute_participation_record` refreshes the cache for proposer eligibility
/// (#1530). `evaluate_consequence_rules` checks whether the outlet invocation
/// triggered any consequence rules (#1531).
pub fn post_outlet_invocation_bookkeeping<S: std::hash::BuildHasher>(
    events: &[scp_event_log::Event],
    invoker_did: &DID,
    context_id: &str,
    now: u64,
    convergent_now: u64,
    participation_cache: &mut std::collections::HashMap<
        String,
        scp_protocol::trust::participation::ParticipationRecord,
        S,
    >,
    consequence_rules: &[scp_protocol::trust::consequence::ConsequenceRule],
) -> Vec<scp_protocol::trust::consequence::TriggeredConsequence> {
    // Update participation record after outlet execution (#1530).
    if !events.is_empty()
        && let Ok(record) = scp_protocol::trust::participation::compute_participation_record(
            events,
            invoker_did.as_ref(),
            context_id,
            [0u8; 32],
            now,
            // attestation_count is a credential-layer, verifier-relative fact
            // (§7.3.2); this outlet-invoke path gates only on participation_count
            // and has no attestation-cache access, so it passes an empty
            // accessible-attestation set (count 0) by design — NOT a stub.
            &[],
        )
    {
        participation_cache.insert(invoker_did.to_string(), record);
    }

    // Evaluate consequence rules after outlet execution (#1531).
    // The caller is responsible for enforcing triggered consequences via
    // enforce_triggered_consequences on the PerContextState.
    evaluate_consequence_rules(
        consequence_rules,
        events,
        invoker_did.as_ref(),
        now,
        convergent_now,
    )
}

/// Validates the spending side of AND-composition for paid outlet invocations
/// (spec §19.5).
///
/// Per spec §19.5, paid actions require BOTH an action capability AND a
/// spending UCAN. The action capability is verified UPSTREAM at the
/// `OutletCall` / `OutletCallAll` `member_has_capability` gate (see
/// `invoke_outlet`). This function verifies the spending side only.
///
/// # Errors
///
/// Returns [`InvocationError::ExecutionFailed`] if the spending UCAN is
/// missing for a paid action or if the spending capability is malformed.
pub fn check_outlet_spending_capability(
    action_cost: scp_protocol::economy::types::Amount,
    spending_ucan: Option<&UcanToken>,
) -> Result<(), InvocationError> {
    // Convert economy Amount to UCAN spending Amount (both are u64 wrappers).
    let ucan_amount = scp_protocol::crypto::ucan::spending::Amount(action_cost.0);
    scp_protocol::crypto::ucan::spending::check_spending_capability(
        spending_ucan,
        ucan_amount,
        "outlet:call",
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
    economy: &Option<&mut OutletEconomyContext<'_, S>>,
) -> Option<EscrowParts> {
    let econ = economy.as_ref()?;
    let adapter = econ.payment_adapter.as_ref().map(std::sync::Arc::clone)?;
    let policy = econ.economic_policy?.clone();
    let metrics = econ.metrics.clone();
    let context_id = econ.context_id.to_owned();
    Some((adapter, policy, metrics, context_id))
}

/// Completes the escrow payment after successful outlet execution, or rolls back
/// the budget on capture failure.
///
/// Returns the payment receipt (if any). On capture failure, rolls back budget
/// and returns the error.
async fn finalize_outlet_escrow<S: BuildHasher>(
    escrow: Option<crate::economy::integration::PreparedAction>,
    escrow_parts: Option<&EscrowParts>,
    action_cost: Option<scp_protocol::economy::types::Amount>,
    economy: &mut Option<&mut OutletEconomyContext<'_, S>>,
    invoker_did: &DID,
) -> Result<Option<crate::economy::adapter::PaymentReceipt>, InvocationError> {
    if let (Some(prepared), Some((adapter, policy, metrics, _))) = (escrow, escrow_parts) {
        match complete_outlet_payment(adapter.as_ref(), Some(policy), &prepared, metrics).await {
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

/// Voids the payment escrow and rolls back budget on outlet failure.
///
/// Combines the void + rollback pattern that appears in every failure branch
/// of `invoke_outlet` and `invoke_outlet_with_cancellation`.
async fn void_escrow_and_rollback<S: BuildHasher>(
    escrow: Option<&crate::economy::integration::PreparedAction>,
    escrow_parts: Option<&EscrowParts>,
    action_cost: Option<scp_protocol::economy::types::Amount>,
    economy: &mut Option<&mut OutletEconomyContext<'_, S>>,
    invoker_did: &DID,
) {
    if let (Some(prepared), Some((adapter, _, _, _))) = (escrow, escrow_parts) {
        void_outlet_escrow(adapter.as_ref(), prepared).await;
    }
    if let Some(cost) = action_cost
        && let Some(econ) = economy
    {
        econ.budget_tracker.reverse_spend(invoker_did, cost);
    }
}

// ---------------------------------------------------------------------------
// Escrow payment flow for outlet invocations (#1537)
// ---------------------------------------------------------------------------

/// Authorizes a outlet payment (escrow step 1).
///
/// Creates an escrow hold via `prepare_paid_action`. Returns the prepared
/// action for later completion or voiding. Returns `None` when cost is zero
/// or no payment is needed.
///
/// Called BEFORE outlet execution. On success, the caller must eventually call
/// `complete_outlet_payment` or `void_outlet_escrow`.
pub(crate) async fn authorize_outlet_payment(
    adapter: &dyn crate::economy::adapter::PaymentAdapterDyn,
    policy: &scp_protocol::economy::types::EconomicPolicy,
    context_id: &str,
    invoker_did: &DID,
    metrics: &scp_protocol::economy::policy::ObservableMetrics,
) -> Result<Option<crate::economy::integration::PreparedAction>, InvocationError> {
    let cost = scp_protocol::economy::policy::evaluate_cost(
        policy,
        &scp_protocol::economy::types::PaidActionType::OutletCall,
        metrics,
    );
    let Some(cost) = cost.filter(|c| c.0 > 0) else {
        return Ok(None);
    };

    let metadata = crate::economy::adapter::PaymentMetadata {
        action_type: scp_protocol::economy::types::PaidActionType::OutletCall,
        context_id: Some(context_id.to_owned()),
        idempotency_key: *uuid::Uuid::new_v4().as_bytes(),
    };

    let prepared = crate::economy::integration::prepare_paid_action(
        adapter,
        Some(policy),
        scp_protocol::economy::types::PaidActionType::OutletCall,
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

/// Completes a outlet payment (escrow step 2: capture).
///
/// Called AFTER successful outlet execution. Captures the escrowed payment
/// and returns the receipt.
pub(crate) async fn complete_outlet_payment(
    adapter: &dyn crate::economy::adapter::PaymentAdapterDyn,
    policy: Option<&scp_protocol::economy::types::EconomicPolicy>,
    prepared: &crate::economy::integration::PreparedAction,
    metrics: &scp_protocol::economy::policy::ObservableMetrics,
) -> Result<Option<crate::economy::adapter::PaymentReceipt>, InvocationError> {
    let processed = crate::economy::integration::process_paid_action(
        adapter,
        policy,
        &prepared.envelope,
        metrics,
        |payload| async move { Ok(payload) },
    )
    .await
    .map_err(|_| InvocationError::ExecutionFailed {
        message: "payment capture failed after successful outlet execution".to_owned(),
    })?;

    if let Some(receipt) = &processed.receipt {
        tracing::debug!(
            receipt_id = %hex::encode(receipt.receipt_id),
            adapter_id = %receipt.adapter_id,
            "outlet invocation payment receipt captured"
        );
    }

    Ok(processed.receipt)
}

/// Voids a outlet payment escrow on failure.
///
/// Called when outlet execution fails (error, timeout, cancellation) to
/// release the escrow hold. Best-effort — logs but does not propagate
/// void failures.
pub(crate) async fn void_outlet_escrow(
    adapter: &dyn crate::economy::adapter::PaymentAdapterDyn,
    prepared: &crate::economy::integration::PreparedAction,
) {
    if let Some(ref authorization) = prepared.envelope.authorization
        && let Err(e) = adapter.void_dyn(authorization).await
    {
        tracing::warn!("failed to void outlet payment escrow: {e}");
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

/// Checks whether a member has the `OutletCall(outlet_id)` or `OutletCallAll`
/// capability.
///
/// This is the integration point between the invocation module and the
/// UCAN-based role system (ADR-009). It is a thin wrapper that delegates to
/// [`scp_protocol::context::outlets::has_outlet_call_capability`] — the single
/// source of truth for outlet-call capability checks — so the runtime and
/// protocol layers cannot drift.
#[must_use]
pub fn has_outlet_call_capability(
    role_state: &ContextRoleState,
    did: &str,
    outlet_id: &str,
) -> bool {
    scp_protocol::context::outlets::has_outlet_call_capability(role_state, did, outlet_id)
}

/// Checks whether a member has the `OutletQuery(outlet_id)` or `OutletQueryAll`
/// capability (Query outlets — SCP-OUT-014, spec §5.4.2).
///
/// Mirror of [`has_outlet_call_capability`] for the Query-class stem. Thin
/// wrapper delegating to the single source of truth in
/// [`scp_protocol::context::outlets::has_outlet_query_capability`] so runtime
/// and protocol layers cannot drift.
#[must_use]
pub fn has_outlet_query_capability(
    role_state: &ContextRoleState,
    did: &str,
    outlet_id: &str,
) -> bool {
    scp_protocol::context::outlets::has_outlet_query_capability(role_state, did, outlet_id)
}

/// Checks whether a member holds the kind-appropriate split capability for
/// invoking an outlet.
///
/// Selects between [`has_outlet_call_capability`] (Action) and
/// [`has_outlet_query_capability`] (Query) based on the outlet's registered
/// [`scp_protocol::context::outlets::OutletKind`]. Per spec §5.4.2 the two
/// stems are independent — `OutletQueryAll` must not authorize an Action call
/// and vice versa. This is the defense-in-depth role-state gate that mirrors
/// the primary UCAN stem selection in [`validate_outlet_invocation_ucan`].
#[must_use]
pub fn has_outlet_invocation_capability(
    role_state: &ContextRoleState,
    did: &str,
    outlet_id: &str,
    kind: scp_protocol::context::outlets::OutletKind,
) -> bool {
    scp_protocol::context::outlets::has_outlet_invocation_capability(
        role_state, did, outlet_id, kind,
    )
}

// ---------------------------------------------------------------------------
// UCAN validation at outlet invocation boundary (#319)
// ---------------------------------------------------------------------------

/// Validates a UCAN token for outlet invocation authorization.
///
/// Parses the encoded JWT token and runs the full 11-step ADR-016 validation
/// pipeline. The required capability stem is selected from the outlet's
/// registered [`scp_protocol::context::outlets::OutletKind`] (SCP-OUT-014):
/// `outlet_query:{outlet_id}` / `outlet_query:*` for Query outlets and
/// `outlet_call:{outlet_id}` / `outlet_call:*` for Action outlets. The two
/// stems are independent, so a cross-class delegation (e.g. parent
/// `outlet_query:*` → child `outlet_call:x`) is rejected automatically because
/// the `CapabilityUri` `resource` strings differ.
///
/// This is the primary authorization gate for outlet invocations. Role-based
/// `has_outlet_invocation_capability` remains as defense-in-depth.
///
/// # Arguments
///
/// * `encoded_token` — JWT-encoded UCAN token.
/// * `context_id` — The context ID the outlet belongs to.
/// * `outlet_name` — The name of the outlet being invoked.
/// * `kind` — The outlet's registered [`scp_protocol::context::outlets::OutletKind`],
///   which selects the required capability stem.
/// * `ctx` — The validation context with resolvers, trackers, and ceiling.
///
/// # Errors
///
/// Returns [`UcanError`] if the token is malformed, expired, revoked, lacks
/// the required capability, or fails any of the 11 validation steps.
///
/// See spec §6.2, §8, §5.4.2, ADR-016, and issue #319.
pub fn validate_outlet_invocation_ucan<D, N, R, P, S>(
    encoded_token: &str,
    context_id: &str,
    outlet_name: &str,
    kind: scp_protocol::context::outlets::OutletKind,
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
    // SCP-OUT-014: pick the split stem from the outlet's registered kind.
    // Query outlets require `outlet_query:{id}` (or wildcard `outlet_query:*`);
    // Action outlets require `outlet_call:{id}` (or wildcard `outlet_call:*`).
    // Cross-class delegations (parent `outlet_query:*` → child `outlet_call:x`)
    // are rejected automatically by `CapabilityUri::matches` because the
    // `resource` strings differ.
    let resource = match kind {
        scp_protocol::context::outlets::OutletKind::Query => "outlet_query",
        scp_protocol::context::outlets::OutletKind::Action => "outlet_call",
    };
    let required_cap = CapabilityUri::new(context_id, resource, outlet_name);
    validate_ucan(&parsed, &required_cap, ctx)
}

// ===========================================================================
// Streaming-native executor + settlement seams (ADR-049 §5 / spec §5.4.5).
// Ported from the outlet-redesign reference invoke.rs. Prerequisite for the
// dispatch pump (dispatch.rs). See ADR-061 + §6.2.5.
//
// NOTE: the reference's InMemory* sink impls are intentionally omitted —
// they back their Vec with std::sync::Mutex, banned in scp-runtime by
// ADR-049 §Decision 12 (crates/scp-runtime/clippy.toml). They are neither a
// listed seam nor a transitive dependency of the pump; callers wire their own.
// ===========================================================================

/// Error returned by [`OutletExecutor`] methods.
///
/// Distinct from [`InvocationError`] because executor-level failures are an
/// inner detail of the outlet implementation, not a protocol-level failure
/// of the invocation pipeline. The [`OutletExecutor`] adapter
/// ([`invoke_outlet_dispatch`]) maps these into the protocol-level
/// taxonomy:
///
/// | Variant                 | Maps to                                         |
/// |-------------------------|-------------------------------------------------|
/// | [`KindMismatch`]        | [`InvocationError::KindMismatch`]               |
/// | [`QueryViolation`]      | [`InvocationError::QueryViolation`]             |
/// | [`Failed`]              | [`InvocationError::ExecutionFailed`]            |
///
/// [`KindMismatch`]: OutletExecutorError::KindMismatch
/// [`QueryViolation`]: OutletExecutorError::QueryViolation
/// [`Failed`]: OutletExecutorError::Failed
#[derive(Debug, thiserror::Error)]
pub enum OutletExecutorError {
    /// Returned by the default [`OutletExecutor::exec_query`] /
    /// [`OutletExecutor::exec_action`] implementation when an executor was
    /// dispatched against the wrong half — i.e., a Query-registered outlet
    /// whose implementor only overrode `exec_action` (or vice versa). This
    /// is the structural misdeclaration signal: the runtime cannot dispatch
    /// to a half the implementor did not provide.
    #[error("outlet executor kind mismatch (expected {expected:?})")]
    KindMismatch {
        /// The kind for which the implementor failed to provide an executor
        /// half. For Query, the misdeclaration signal in spec §5.4.2 fires.
        expected: scp_protocol::context::outlets::OutletKind,
    },
    /// Returned by [`MutableInvocation`] write methods when the underlying
    /// registered outlet is `OutletKind::Query` (defense-in-depth runtime
    /// check against type-system bypass). Spec §5.4.2 `QueryViolation`.
    #[error("Query outlet attempted write \"{operation}\" through MutableInvocation (§5.4.2)")]
    QueryViolation {
        /// The denied operation (e.g., `"send_message"`).
        operation: &'static str,
    },
    /// Application-level executor failure. Equivalent to the `String` returned
    /// by closure-based callers; preserved verbatim for compatibility.
    #[error("outlet executor failed: {0}")]
    Failed(String),
}

/// Pending mutation queued on a [`MutableInvocation`].
///
/// Action outlets describe their writes by enqueuing typed [`MutationIntent`]
/// records on the handle. The runtime drains the intents after the executor
/// returns successfully and applies them through the existing per-context
/// mutation pipeline (governance, role assignment, registry updates,
/// economic ledgers, caveat counter store, event log append). For
/// [`OutletKind::Query`] outlets the intents are unreachable — write methods
/// only exist on [`MutableInvocation`] which is only constructed for
/// `OutletKind::Action` (type-system enforcement of the deny-list).
///
/// The runtime check on every [`MutableInvocation`] write method is
/// defense-in-depth: a `MutableInvocation` whose `kind == Query` (constructed
/// directly in tests, or surfaced through a future API misuse) refuses every
/// mutation and emits the `QueryMisdeclaration` signal per §5.4.2.
///
/// [`OutletKind::Query`]: scp_protocol::context::outlets::OutletKind::Query
#[derive(Debug, Clone)]
pub enum MutationIntent {
    /// Send an MLS application message into the context (deny-list:
    /// "messages"). The runtime hands the payload to
    /// `ContextManager::send_message` after `exec_action` returns.
    SendMessage {
        /// Opaque application payload.
        payload: serde_json::Value,
    },
    /// Assign a role to a member (deny-list: "roles").
    AssignRole {
        /// The member receiving the role assignment.
        member_did: String,
        /// The role name to assign.
        role: String,
    },
    /// Register a new outlet in the context registry (deny-list: "registry").
    RegisterOutlet {
        /// Canonical-bytes-equivalent registration payload (caller-prepared
        /// so the runtime can verify against `OutletRegistration::validate`).
        registration: serde_json::Value,
    },
    /// Append an event log entry (deny-list: "event log"). The runtime
    /// appends through the per-context Merkle event log provider.
    AppendEvent {
        /// Caller-prepared event payload (kind + opaque data).
        event: serde_json::Value,
    },
    /// Submit a governance proposal (deny-list: "governance proposals").
    SubmitGovernanceProposal {
        /// Caller-prepared proposal envelope.
        proposal: serde_json::Value,
    },
    /// Cast a governance vote (deny-list: "governance votes").
    CastGovernanceVote {
        /// Proposal ID being voted on.
        proposal_id: String,
        /// Yes / No / Abstain encoded by the runtime.
        vote: serde_json::Value,
    },
    /// Debit an economic ledger entry (deny-list: "economic ledgers").
    DebitEconomicLedger {
        /// The DID being charged.
        did: String,
        /// Amount in the context's economic policy currency.
        amount: u64,
    },
    /// Credit an economic ledger entry (deny-list: "economic ledgers").
    CreditEconomicLedger {
        /// The DID receiving the credit.
        did: String,
        /// Amount in the context's economic policy currency.
        amount: u64,
    },
    /// Increment a per-DID caveat counter (deny-list: "caveat counter store").
    IncrementCaveatCounter {
        /// Counter key (caveat-defined identifier).
        key: String,
        /// Increment delta — always positive by convention; counters are
        /// monotonic per §7.3.8.
        delta: u64,
    },
}

/// Sink for misdeclaration `OutletVerifiedEvent` signals.
///
/// Receives `OutletVerified { integrity_ok: false, reason:
/// QueryMisdeclaration }` events emitted when a Query outlet's executor
/// trips the [`MutableInvocation`] write deny-list (spec §5.4.2
/// "Misdeclaration signal").
///
/// Implementations are typically a `Vec<OutletVerifiedEvent>` collected by
/// the dispatcher and returned to the caller alongside the invocation
/// outcome. The trait is `Send + Sync` so the sink can be shared across
/// `tokio::spawn`-ed executor tasks.
pub trait QueryMisdeclarationSink: Send + Sync {
    /// Records an integrity-failure signal. Implementations must be
    /// non-blocking — emission happens inline with the executor's failed
    /// write attempt and must not stall the invocation.
    fn record(&self, event: scp_protocol::context::outlets::OutletVerifiedEvent);
}

/// Sink for `OutletVerifiedEvent { integrity_ok: false, reason:
/// HandlerPanicked }` signals (SCP-OUT-028).
///
/// Receives a parallel `OutletVerified` event whenever the runtime's
/// `catch_unwind` guard around an executor call recovers a panic (ADR-049
/// §148). The signal is operator-attributable per spec §5.4.2 — panics are
/// protocol-visible signals of an outlet operator's defect, NOT SDK-internal
/// bugs (the SDK is the entity that catches the panic).
///
/// Implementations are typically a `Vec<OutletVerifiedEvent>` collected by
/// the runtime and surfaced to the manager for event-log emission. The trait
/// is `Send + Sync` so the sink can be shared across `tokio::spawn`-ed
/// executor tasks.
///
/// This is a parallel sink to [`QueryMisdeclarationSink`] — both surface
/// `OutletVerifiedEvent { integrity_ok: false, .. }` records but with
/// distinct `reason` discriminants (`QueryMisdeclaration` vs
/// `HandlerPanicked`). Two sinks rather than one shared trait keeps the
/// runtime contract crisp: a caller wires only the panic guard or only the
/// misdeclaration guard, not both.
pub trait HandlerPanicSink: Send + Sync {
    /// Records an integrity-failure signal for a handler panic.
    /// Implementations must be non-blocking — emission happens inline with
    /// the recovered panic and must not stall the invocation.
    fn record(&self, event: scp_protocol::context::outlets::OutletVerifiedEvent);
}

/// Sink for the single [`OutletInvokedEvent`] emitted at the close of
/// each outlet stream (§5.4.5 event-log shape; SCP-OUT-035).
///
/// The streaming executor task ([`run_streaming_executor_task`])
/// accumulates the chunk sequence, builds the §5.4.5 event when the
/// terminal chunk is delivered to the receiver, and calls
/// [`Self::record`] once. The sink is the runtime-side hand-off from
/// the spawned task to the caller's event-log append path: the caller
/// owns the storage / Merkle bookkeeping, and the trait is `Send +
/// Sync` so it can be shared across `tokio::spawn`-ed executor tasks
/// without an extra mutex.
///
/// Per ADR-049 §5 / spec §5.4.5, EVERY outlet invocation produces
/// exactly one `OutletInvokedEvent`, even when the executor never
/// emits a `Data` chunk (e.g., a terminal `Error` before any payload).
/// Implementations MUST be idempotent against double-record (the
/// runtime guarantees a single call per task; defense-in-depth keeps
/// the contract crisp).
pub trait OutletInvokedEventSink: Send + Sync {
    /// Records the §5.4.5 stream-close event. Called exactly once per
    /// outlet stream, after the terminal chunk has been delivered to
    /// the chunk receiver.
    fn record(&self, event: OutletInvokedEvent);
}

/// The §5.4.5 close-time economic settlement of a streaming-native
/// invocation (E1 remediation).
///
/// The open-time escrow HOLD was DEBITED against the invoker's
/// `MemberBudgetTracker` at acceptance (and topped up per accepted credit
/// grant). At terminal-chunk delivery the runtime knows the exact billed
/// amount and the unspent refund:
///
/// - `reserved == billed_amount + refund_amount` — the total hold debited.
/// - `billed_amount` — `cost_per_chunk × billable Data chunks at/below the
///   cancel-ack sequence`. This is the amount the invoker actually pays.
/// - `refund_amount` — the unspent portion, refunded to the invoker via
///   `MemberBudgetTracker::reverse_spend` so net spent == `billed_amount`.
///
/// A stream that terminates with `Error { terminal: true }` before any
/// Data chunk yields `billed_amount == 0` and a full refund.
#[derive(Debug, Clone)]
pub struct StreamSettlement {
    /// Hosting context id — the lock the refund + receipt take.
    pub context_id: String,
    /// The §5.4.5 `invoker_did` whose budget was held and is now settled.
    pub invoker_did: DID,
    /// Total escrow debited at open + grants (`billed + refund`). Recorded
    /// for audit / receipt provenance.
    pub reserved: scp_protocol::economy::types::Amount,
    /// Amount the invoker is billed (net spent after refund).
    pub billed_amount: scp_protocol::economy::types::Amount,
    /// Unspent escrow refunded to the invoker (`reserved - billed`).
    pub refund_amount: scp_protocol::economy::types::Amount,
    /// Count of billable Data chunks (the §5.4.5 `chunks_billed`).
    pub billed_count: u32,
    /// Stream `request_id` — receipt + event-log provenance.
    pub request_id: RequestId,
    /// Outlet id — receipt + event-log provenance.
    pub outlet_id: OutletId,
    /// §5.4.5 MED-HIGH — the economic policy snapshotted at
    /// `OutletStreamOpen` acceptance (ADR-048 per-instance snapshot; H8
    /// "service rendered is billed"). The settlement path prefers the LIVE
    /// per-context policy when the hosting context is still registered, but
    /// when the context was closed / evicted mid-stream the live policy is
    /// gone — the snapshot lets the runtime STILL capture the
    /// `PaymentReceipt` for service already rendered (and record a durable
    /// `PaymentCaptureFailed` on capture failure) rather than stranding the
    /// bill behind a `ContextNotRegistered` early-return. `None` for
    /// zero-cost / Query streams and legacy/test callers without an
    /// economic policy at open.
    pub economic_policy_snapshot: Option<EconomicPolicySnapshot>,
    /// The WORST-CASE cumulative amount RESERVED against the
    /// [`CaveatKind::AmountCumulative`](scp_protocol::trust::CaveatKind)
    /// counter at the open-time final gate — `cost_per_chunk ×
    /// effective_max_billable_chunks` (`<= cap` by construction), from
    /// [`super::stream::cumulative_reserve_amount`].
    /// `0` when the cap is absent, `cost_per_chunk == 0`, or no counter store
    /// was wired. Close-time settlement releases the UNSPENT portion —
    /// `amount_cumulative_reserved − billed_count × cost_per_chunk` (saturating)
    /// — back to the counter via [`crate::trust::CaveatCounterApi::release`], so
    /// the cumulative cap is debited by exactly the billed spend rather than the
    /// worst-case reservation, regardless of how small the declared estimate
    /// was.
    pub amount_cumulative_reserved: u64,
    /// The invoker-declared `estimated_chunk_count` (diagnostics / event field
    /// only). NOT the count the reserve was computed over — the reserve is the
    /// worst-case spend and the close-time release reconciles by AMOUNT
    /// (`unspent = amount_cumulative_reserved − billed_count × cost_per_chunk`).
    pub reserved_chunks: u32,
    /// R4 HIGH-1 — the opening UCAN CID, the key the
    /// [`CaveatKind::AmountCumulative`](scp_protocol::trust::CaveatKind)
    /// counter is stored under. Needed so the close-time release targets the
    /// same counter the open-time reserve incremented. Empty for legacy / test
    /// callers with no durable counter reservation.
    pub ucan_cid: String,
    /// R4 HIGH-1 — the per-billable-chunk cost, the unit the cumulative
    /// release multiplies the unspent chunk count by. `Amount::new(0)` for
    /// zero-cost / Query streams (release is then a no-op).
    pub cost_per_chunk: scp_protocol::economy::types::Amount,
}

/// §5.4.5 MED-HIGH — economic state snapshotted at `OutletStreamOpen`
/// acceptance so close-time settlement survives a mid-stream context
/// teardown.
///
/// The hosting context's `economic_policy` (which carries the `payee` and
/// `cost_schedule.currency` the payment adapter needs to authorize +
/// capture) is cloned into this snapshot at open. If the context is still
/// registered at settlement the runtime reads the LIVE policy (it may have
/// changed via governance); if the context is GONE, the runtime falls back
/// to this snapshot so the receipt for already-rendered service is still
/// captured. The payment-adapter handle itself lives on the
/// `ContextManager` (not per-context), so it is available regardless of
/// context liveness and is not part of the snapshot.
#[derive(Debug, Clone)]
pub struct EconomicPolicySnapshot {
    /// The hosting context's economic policy at open. Carries `payee` and
    /// `cost_schedule.currency` for the `authorize → capture` adapter
    /// sequence.
    pub policy: scp_protocol::economy::types::EconomicPolicy,
}

/// Sink fired once at the close of each streaming-native outlet invocation.
///
/// Performs the §5.4.5 economic settlement (E1 remediation): refund the
/// unspent escrow, issue a §19.15.5 `PaymentReceipt` for the billed amount,
/// and append the close event to the event log.
///
/// The dispatch pump fires this from inside its spawned `tokio` task at the
/// settlement block (gated by the `pump_exited` flag so it fires at most
/// once). Because it runs ON the pump's tokio task, the implementation MUST
/// NOT `block_on` — the production native-bridge impls hold a
/// [`tokio::runtime::Handle`] and `Handle::spawn` the async
/// `ContextManager::outlet_stream_settle`. The trait is `Send + Sync` so it
/// can be shared into the spawned pump task without an extra mutex.
///
/// `None` (no sink wired) disables settlement — the legacy / test open
/// paths that do not thread a `ContextManager` handle. The escrow ledger's
/// `(billed, refund)` are still surfaced via the `StreamCloseSummary` for
/// those callers.
pub trait StreamSettlementSink: Send + Sync {
    /// Settles the stream's economics exactly once. MUST NOT block — spawn
    /// the async settlement onto a runtime handle.
    fn settle(&self, settlement: StreamSettlement);
}

/// Read-only handle exposed to a [`OutletKind::Query`] outlet's executor.
///
/// Spec §5.4.2: "The runtime invokes Query outlets through a
/// `ReadOnlyInvocation` handle that denies writes to context state
/// (messages, roles, registry, event log, governance, economic ledgers).
/// Any attempt by an executor to mutate through this handle returns
/// `OutletErrorClass::Protocol::QueryViolation`."
///
/// The deny-list is enforced **at the type level** — none of the seven
/// write surfaces (`messages`, `roles`, `registry`, `event log`,
/// `governance proposals/votes`, `economic ledgers`, `caveat counter
/// store`) have method definitions on this struct. The compiler refuses
/// any executor that calls a write method on a `&ReadOnlyInvocation`.
///
/// Read-side surface (per PRD AC2): [`list_members`], [`get_member_role`],
/// [`get_outlet`], [`list_outlets`], [`get_event`], [`current_epoch`],
/// [`get_economic_policy`], [`get_caveat_counter`].
///
/// [`OutletKind::Query`]: scp_protocol::context::outlets::OutletKind::Query
/// [`list_members`]: ReadOnlyInvocation::list_members
/// [`get_member_role`]: ReadOnlyInvocation::get_member_role
/// [`get_outlet`]: ReadOnlyInvocation::get_outlet
/// [`list_outlets`]: ReadOnlyInvocation::list_outlets
/// [`get_event`]: ReadOnlyInvocation::get_event
/// [`current_epoch`]: ReadOnlyInvocation::current_epoch
/// [`get_economic_policy`]: ReadOnlyInvocation::get_economic_policy
/// [`get_caveat_counter`]: ReadOnlyInvocation::get_caveat_counter
pub struct ReadOnlyInvocation<'a> {
    context: &'a ContextHandle,
    role_state: &'a ContextRoleState,
    registry: &'a OutletRegistry,
    invoker_did: &'a DID,
    outlet_id: &'a OutletId,
    /// Snapshot of event log entries available at invocation time.
    events: &'a [scp_event_log::Event],
    /// Current MLS group epoch at invocation time.
    epoch: u64,
    /// Optional economic policy snapshot for read-side accessors.
    economic_policy: Option<&'a scp_protocol::economy::types::EconomicPolicy>,
    /// Optional caveat counter store snapshot — `(member_did, counter_key) ->
    /// current value`. Pure read view; writes go through Action outlets.
    caveat_counters: Option<&'a std::collections::HashMap<(String, String), u64>>,
}

impl<'a> ReadOnlyInvocation<'a> {
    /// Constructs a read-only invocation handle.
    ///
    /// Constructed by the runtime ([`invoke_outlet_dispatch`]) — outlets do
    /// not build this themselves.
    #[allow(clippy::too_many_arguments)] // matches the read-side accessor surface; cheap to extend
    #[must_use]
    pub const fn new(
        context: &'a ContextHandle,
        role_state: &'a ContextRoleState,
        registry: &'a OutletRegistry,
        invoker_did: &'a DID,
        outlet_id: &'a OutletId,
        events: &'a [scp_event_log::Event],
        epoch: u64,
        economic_policy: Option<&'a scp_protocol::economy::types::EconomicPolicy>,
        caveat_counters: Option<&'a std::collections::HashMap<(String, String), u64>>,
    ) -> Self {
        Self {
            context,
            role_state,
            registry,
            invoker_did,
            outlet_id,
            events,
            epoch,
            economic_policy,
            caveat_counters,
        }
    }

    /// Context ID this invocation is scoped to.
    #[must_use]
    pub fn context_id(&self) -> &str {
        self.context.context_id()
    }

    /// DID of the caller who invoked this Query outlet.
    #[must_use]
    pub const fn invoker_did(&self) -> &DID {
        self.invoker_did
    }

    /// The Query outlet's own ID.
    #[must_use]
    pub const fn outlet_id(&self) -> &OutletId {
        self.outlet_id
    }

    /// Lists all member DIDs currently in the context (PRD AC2).
    #[must_use]
    pub fn list_members(&self) -> Vec<&str> {
        self.role_state.members.iter().map(String::as_str).collect()
    }

    /// Returns the role assigned to `member_did`, if any (PRD AC2).
    #[must_use]
    pub fn get_member_role(&self, member_did: &str) -> Option<&str> {
        self.role_state
            .assignments
            .get(member_did)
            .map(|a| a.role_name.as_str())
    }

    /// Returns the registered outlet metadata for `outlet_id`, if registered
    /// (PRD AC2).
    #[must_use]
    pub fn get_outlet(
        &self,
        outlet_id: &OutletId,
    ) -> Option<&scp_protocol::context::outlets::registry::OutletRegistration> {
        self.registry.get(outlet_id)
    }

    /// Lists all registered outlet IDs in the context registry (PRD AC2).
    #[must_use]
    pub fn list_outlets(&self) -> Vec<&OutletId> {
        self.registry.outlet_ids().collect()
    }

    /// Returns the event-log entry at `index` from the snapshot held for this
    /// invocation, if present (PRD AC2). The snapshot is read-only — writes
    /// through this handle are impossible (no method defined).
    #[must_use]
    pub fn get_event(&self, index: usize) -> Option<&scp_event_log::Event> {
        self.events.get(index)
    }

    /// Returns the number of event-log entries visible to this invocation.
    /// Companion to [`get_event`](Self::get_event).
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Returns the MLS group epoch at the time this invocation was dispatched
    /// (PRD AC2).
    #[must_use]
    pub const fn current_epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the context's current economic policy snapshot, if configured
    /// (PRD AC2). Read-only — Query outlets cannot mutate economic state.
    #[must_use]
    pub const fn get_economic_policy(
        &self,
    ) -> Option<&scp_protocol::economy::types::EconomicPolicy> {
        self.economic_policy
    }

    /// Returns the current caveat counter value for
    /// `(member_did, counter_key)` if a counter store snapshot was supplied
    /// (PRD AC2). Read-only — increments go through Action outlets'
    /// [`MutableInvocation::increment_caveat_counter`].
    #[must_use]
    pub fn get_caveat_counter(&self, member_did: &str, counter_key: &str) -> Option<u64> {
        self.caveat_counters
            .and_then(|map| map.get(&(member_did.to_owned(), counter_key.to_owned())))
            .copied()
    }
}

/// Mutable handle exposed to a [`OutletKind::Action`] outlet's executor.
///
/// Spec §5.4.2: "Action executors may mutate context state through SDK-provided
/// handles subject to role and capability checks." This is the SDK-provided
/// handle. It exposes the same read methods as [`ReadOnlyInvocation`] plus
/// the write methods that Action outlets need to mutate context state.
///
/// Writes are recorded as typed [`MutationIntent`] records and drained by the
/// runtime after `exec_action` returns successfully — the executor never
/// holds a manager reference and never directly mutates per-context state.
/// The runtime is the sole entity that applies mutations, ensuring the
/// existing locking and rollback contracts in
/// [`ContextManager::invoke_outlet_with_economy`](crate::context::ContextManager::invoke_outlet_with_economy)
/// still hold.
///
/// **Defense-in-depth runtime check.** Every write method calls
/// [`guard_kind`](Self::guard_kind) before enqueuing the intent. If the
/// captured `kind` is [`OutletKind::Query`] (a misdeclaration the type
/// system did not catch — for example, a test that constructs the handle
/// directly), the method returns
/// [`OutletExecutorError::QueryViolation`] and emits an
/// `OutletVerifiedEvent { integrity_ok: false, reason: QueryMisdeclaration }`
/// through the configured [`QueryMisdeclarationSink`].
///
/// [`OutletKind::Action`]: scp_protocol::context::outlets::OutletKind::Action
/// [`OutletKind::Query`]: scp_protocol::context::outlets::OutletKind::Query
pub struct MutableInvocation<'a> {
    inner: ReadOnlyInvocation<'a>,
    /// The kind the handle was constructed for. Action invocations get
    /// `OutletKind::Action`; the runtime check refuses writes when this is
    /// `Query` (defense-in-depth).
    kind: scp_protocol::context::outlets::OutletKind,
    /// Pending writes accumulated during executor execution.
    pending: Vec<MutationIntent>,
    /// Optional sink for `OutletVerified` integrity-failure events emitted
    /// when [`guard_kind`](Self::guard_kind) refuses a write. `None` is
    /// permitted (e.g. tests that only assert the error variant).
    misdeclaration_sink: Option<&'a dyn QueryMisdeclarationSink>,
}

impl<'a> MutableInvocation<'a> {
    /// Constructs a mutable invocation handle.
    ///
    /// `kind` should always be [`OutletKind::Action`] in production —
    /// [`invoke_outlet_dispatch`] only constructs `MutableInvocation` after
    /// confirming the outlet's registered kind is `Action`. Test code may
    /// construct the handle with `kind == Query` to exercise the
    /// defense-in-depth runtime deny-list (PRD AC7).
    ///
    /// [`OutletKind::Action`]: scp_protocol::context::outlets::OutletKind::Action
    #[must_use]
    pub fn new(
        inner: ReadOnlyInvocation<'a>,
        kind: scp_protocol::context::outlets::OutletKind,
        misdeclaration_sink: Option<&'a dyn QueryMisdeclarationSink>,
    ) -> Self {
        Self {
            inner,
            kind,
            pending: Vec::new(),
            misdeclaration_sink,
        }
    }

    // -----------------------------------------------------------------------
    // Read-side surface — delegates to the inner ReadOnlyInvocation. Action
    // outlets read context state the same way Query outlets do.
    // -----------------------------------------------------------------------

    /// See [`ReadOnlyInvocation::context_id`].
    #[must_use]
    pub fn context_id(&self) -> &str {
        self.inner.context_id()
    }

    /// See [`ReadOnlyInvocation::invoker_did`].
    #[must_use]
    pub const fn invoker_did(&self) -> &DID {
        self.inner.invoker_did()
    }

    /// See [`ReadOnlyInvocation::outlet_id`].
    #[must_use]
    pub const fn outlet_id(&self) -> &OutletId {
        self.inner.outlet_id()
    }

    /// See [`ReadOnlyInvocation::list_members`].
    #[must_use]
    pub fn list_members(&self) -> Vec<&str> {
        self.inner.list_members()
    }

    /// See [`ReadOnlyInvocation::get_member_role`].
    #[must_use]
    pub fn get_member_role(&self, member_did: &str) -> Option<&str> {
        self.inner.get_member_role(member_did)
    }

    /// See [`ReadOnlyInvocation::get_outlet`].
    #[must_use]
    pub fn get_outlet(
        &self,
        outlet_id: &OutletId,
    ) -> Option<&scp_protocol::context::outlets::registry::OutletRegistration> {
        self.inner.get_outlet(outlet_id)
    }

    /// See [`ReadOnlyInvocation::list_outlets`].
    #[must_use]
    pub fn list_outlets(&self) -> Vec<&OutletId> {
        self.inner.list_outlets()
    }

    /// See [`ReadOnlyInvocation::get_event`].
    #[must_use]
    pub fn get_event(&self, index: usize) -> Option<&scp_event_log::Event> {
        self.inner.get_event(index)
    }

    /// See [`ReadOnlyInvocation::current_epoch`].
    #[must_use]
    pub const fn current_epoch(&self) -> u64 {
        self.inner.current_epoch()
    }

    /// See [`ReadOnlyInvocation::get_economic_policy`].
    #[must_use]
    pub const fn get_economic_policy(
        &self,
    ) -> Option<&scp_protocol::economy::types::EconomicPolicy> {
        self.inner.get_economic_policy()
    }

    /// See [`ReadOnlyInvocation::get_caveat_counter`].
    #[must_use]
    pub fn get_caveat_counter(&self, member_did: &str, counter_key: &str) -> Option<u64> {
        self.inner.get_caveat_counter(member_did, counter_key)
    }

    /// Drains all pending [`MutationIntent`] records, leaving the handle
    /// empty. Called by the dispatcher after `exec_action` returns
    /// successfully.
    #[must_use]
    pub fn take_pending_mutations(&mut self) -> Vec<MutationIntent> {
        std::mem::take(&mut self.pending)
    }

    /// Returns the number of pending mutations (read-only inspection for
    /// tests / debug logging).
    #[must_use]
    pub const fn pending_mutation_count(&self) -> usize {
        self.pending.len()
    }

    /// Returns the kind this handle was constructed for. Test helper.
    #[must_use]
    pub const fn kind(&self) -> scp_protocol::context::outlets::OutletKind {
        self.kind
    }

    // -----------------------------------------------------------------------
    // Write-side surface — present ONLY on MutableInvocation. The compiler
    // refuses any executor that tries to call these on `&ReadOnlyInvocation`
    // (PRD AC1: type-system deny-list).
    //
    // Each method runs `guard_kind` first — defense-in-depth runtime check
    // (PRD AC7) for the case where a `MutableInvocation` is somehow
    // constructed with `kind == Query` (e.g., a future API misuse or a
    // misdeclared outlet whose dispatcher path is bypassed). On Query the
    // method emits the §5.4.2 misdeclaration signal and returns
    // `QueryViolation` without enqueuing the intent.
    // -----------------------------------------------------------------------

    /// Send a context message (deny-list: messages).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] when this handle's
    /// kind is `Query` (defense-in-depth — the type system normally
    /// prevents this).
    pub fn send_message(&mut self, payload: serde_json::Value) -> Result<(), OutletExecutorError> {
        self.guard_kind("send_message")?;
        self.pending.push(MutationIntent::SendMessage { payload });
        Ok(())
    }

    /// Assign a role to a member (deny-list: roles).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn assign_role(
        &mut self,
        member_did: impl Into<String>,
        role: impl Into<String>,
    ) -> Result<(), OutletExecutorError> {
        self.guard_kind("assign_role")?;
        self.pending.push(MutationIntent::AssignRole {
            member_did: member_did.into(),
            role: role.into(),
        });
        Ok(())
    }

    /// Register a new outlet in the context registry (deny-list: registry).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn register_outlet(
        &mut self,
        registration: serde_json::Value,
    ) -> Result<(), OutletExecutorError> {
        self.guard_kind("register_outlet")?;
        self.pending
            .push(MutationIntent::RegisterOutlet { registration });
        Ok(())
    }

    /// Append an entry to the context event log (deny-list: event log).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn append_event(&mut self, event: serde_json::Value) -> Result<(), OutletExecutorError> {
        self.guard_kind("append_event")?;
        self.pending.push(MutationIntent::AppendEvent { event });
        Ok(())
    }

    /// Submit a governance proposal (deny-list: governance proposals).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn submit_governance_proposal(
        &mut self,
        proposal: serde_json::Value,
    ) -> Result<(), OutletExecutorError> {
        self.guard_kind("submit_governance_proposal")?;
        self.pending
            .push(MutationIntent::SubmitGovernanceProposal { proposal });
        Ok(())
    }

    /// Cast a governance vote on an active proposal (deny-list: governance
    /// votes).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn cast_governance_vote(
        &mut self,
        proposal_id: impl Into<String>,
        vote: serde_json::Value,
    ) -> Result<(), OutletExecutorError> {
        self.guard_kind("cast_governance_vote")?;
        self.pending.push(MutationIntent::CastGovernanceVote {
            proposal_id: proposal_id.into(),
            vote,
        });
        Ok(())
    }

    /// Debit an economic ledger entry (deny-list: economic ledgers).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn debit_economic_ledger(
        &mut self,
        did: impl Into<String>,
        amount: u64,
    ) -> Result<(), OutletExecutorError> {
        self.guard_kind("debit_economic_ledger")?;
        self.pending.push(MutationIntent::DebitEconomicLedger {
            did: did.into(),
            amount,
        });
        Ok(())
    }

    /// Credit an economic ledger entry (deny-list: economic ledgers).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn credit_economic_ledger(
        &mut self,
        did: impl Into<String>,
        amount: u64,
    ) -> Result<(), OutletExecutorError> {
        self.guard_kind("credit_economic_ledger")?;
        self.pending.push(MutationIntent::CreditEconomicLedger {
            did: did.into(),
            amount,
        });
        Ok(())
    }

    /// Increment a per-DID caveat counter (deny-list: caveat counter store).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn increment_caveat_counter(
        &mut self,
        key: impl Into<String>,
        delta: u64,
    ) -> Result<(), OutletExecutorError> {
        self.guard_kind("increment_caveat_counter")?;
        self.pending.push(MutationIntent::IncrementCaveatCounter {
            key: key.into(),
            delta,
        });
        Ok(())
    }

    /// Defense-in-depth runtime check.
    ///
    /// On `Query` kind: emits the §5.4.2 misdeclaration signal through the
    /// sink (if configured) and returns [`OutletExecutorError::QueryViolation`].
    /// On `Action` kind: returns `Ok(())`.
    fn guard_kind(&self, operation: &'static str) -> Result<(), OutletExecutorError> {
        if matches!(self.kind, scp_protocol::context::outlets::OutletKind::Query) {
            if let Some(sink) = self.misdeclaration_sink {
                sink.record(scp_protocol::context::outlets::OutletVerifiedEvent {
                    outlet_id: self.inner.outlet_id.clone(),
                    passed: 0,
                    failed: 1,
                    integrity_ok: false,
                    reason: Some(
                        scp_protocol::context::outlets::OutletVerifiedReason::QueryMisdeclaration,
                    ),
                });
            }
            return Err(OutletExecutorError::QueryViolation { operation });
        }
        Ok(())
    }
}

/// Per-outlet executor trait — Query/Action half-and-half.
///
/// Spec §5.4.2: outlets declare a kind and the runtime dispatches Query
/// invocations through [`exec_query`] (read-only handle) and Action
/// invocations through [`exec_action`] (write-capable handle). The trait's
/// default implementations return [`OutletExecutorError::KindMismatch`] so
/// that a misdeclaration — registering as one kind but only implementing
/// the other half — is caught as a distinct, attributable failure rather
/// than as a silent no-op.
///
/// PRD SCP-OUT-013 AC4: "trait `OutletExecutor` has signatures
/// `exec_query(&self, ctx: ReadOnlyInvocation, input: Value) -> Result<Value,
/// OutletError>` and `exec_action(&self, ctx: MutableInvocation, input:
/// Value) -> Result<Value, OutletError>`. Default impls return
/// `OutletError::KindMismatch`."
///
/// **Type-system deny-list (PRD AC1).** `exec_query` receives `&ReadOnlyInvocation`
/// — the compiler refuses any call site that tries to invoke a write
/// method on it because no write methods exist on the type. `exec_action`
/// receives `&mut MutableInvocation` — only this half can enqueue
/// [`MutationIntent`] records.
///
/// [`exec_query`]: OutletExecutor::exec_query
/// [`exec_action`]: OutletExecutor::exec_action
#[async_trait::async_trait]
pub trait OutletExecutor: Send + Sync {
    /// Executes a Query invocation against a read-only handle.
    ///
    /// # Errors
    ///
    /// The default implementation returns [`OutletExecutorError::KindMismatch`]
    /// so that a Query-registered outlet whose implementor only overrode
    /// `exec_action` is caught at runtime per spec §5.4.2 misdeclaration
    /// signal. Implementations override this method to provide the actual
    /// Query semantics.
    async fn exec_query(
        &self,
        ctx: &ReadOnlyInvocation<'_>,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, OutletExecutorError> {
        let _ = (ctx, input);
        Err(OutletExecutorError::KindMismatch {
            expected: scp_protocol::context::outlets::OutletKind::Query,
        })
    }

    /// Executes an Action invocation against a mutable handle.
    ///
    /// # Errors
    ///
    /// The default implementation returns [`OutletExecutorError::KindMismatch`]
    /// so that an Action-registered outlet whose implementor only overrode
    /// `exec_query` is caught. Implementations override this method to
    /// enqueue mutations through `ctx.send_message`, `ctx.assign_role`,
    /// etc., subject to the runtime deny-list (`guard_kind`).
    async fn exec_action(
        &self,
        ctx: &mut MutableInvocation<'_>,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, OutletExecutorError> {
        let _ = (ctx, input);
        Err(OutletExecutorError::KindMismatch {
            expected: scp_protocol::context::outlets::OutletKind::Action,
        })
    }

    /// Executes a Query invocation as a streaming producer (SCP-OUT-033).
    ///
    /// Spec §5.4.5: outlet invocations are streams by construction. The
    /// streaming form lets executors emit `ChunkPayload::Data` /
    /// `ChunkPayload::Progress` chunks as work proceeds rather than
    /// returning a single aggregated value at the end. Non-streaming
    /// executors override [`exec_query`](Self::exec_query) instead — the
    /// default implementation here delegates to `exec_query` and
    /// converts the single returned value into a `Data` chunk via
    /// [`one_shot_to_stream`] (executors get streaming "for free" without
    /// changing their existing code).
    ///
    /// Implementations that override this method MUST NOT emit a
    /// terminal chunk (`End` / `Error { terminal: true }`); the
    /// framework appends `End` after a successful return and `Error`
    /// after a `Result::Err`. Emitting a terminal chunk from inside the
    /// executor races with the framework's own emission and is
    /// undefined behaviour.
    ///
    /// `tx` is bounded — the framework sets the capacity to the §5.4.5
    /// `credit_window` (default 32). When the channel is full,
    /// `tx.send` returns `Err` only if the receiver was dropped (i.e.,
    /// the stream was cancelled); back-pressure stalls the executor
    /// until a downstream consumer drains a slot.
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError`] on any executor-internal failure
    /// (`Failed`), kind mismatch (`KindMismatch`), or query violation
    /// (`QueryViolation`). The framework maps each to a terminal
    /// `ChunkPayload::Error { terminal: true, ... }` and closes the
    /// stream — implementations never write the error chunk themselves.
    async fn exec_query_stream(
        &self,
        ctx: &ReadOnlyInvocation<'_>,
        input: serde_json::Value,
        tx: mpsc::Sender<ChunkPayload>,
    ) -> Result<(), OutletExecutorError> {
        // Default: delegate to non-streaming `exec_query` and emit the
        // single returned value as a `Data` chunk. Non-streaming
        // executors get streaming for free — the framework appends the
        // `End` terminal chunk after this returns successfully.
        let value = self.exec_query(ctx, input).await?;
        one_shot_to_stream(value, &tx).await;
        Ok(())
    }

    /// Executes an Action invocation as a streaming producer (SCP-OUT-033).
    ///
    /// See [`exec_query_stream`](Self::exec_query_stream) for the
    /// streaming contract. The default implementation delegates to
    /// [`exec_action`](Self::exec_action) and emits the single returned
    /// value as a `Data` chunk via [`one_shot_to_stream`].
    ///
    /// Implementations that override this method MUST NOT emit a
    /// terminal chunk (`End` / `Error { terminal: true }`); the
    /// framework owns terminal emission.
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError`] on any executor-internal failure.
    /// The framework maps `Failed` / `KindMismatch` / `QueryViolation`
    /// to a terminal `Error` chunk and closes the stream.
    async fn exec_action_stream(
        &self,
        ctx: &mut MutableInvocation<'_>,
        input: serde_json::Value,
        tx: mpsc::Sender<ChunkPayload>,
    ) -> Result<(), OutletExecutorError> {
        let value = self.exec_action(ctx, input).await?;
        one_shot_to_stream(value, &tx).await;
        Ok(())
    }
}

/// Pushes a single `Value` onto a `ChunkPayload::Data` chunk so a
/// non-streaming executor's return value enters the §5.4.5 stream as a
/// degenerate one-chunk producer (SCP-OUT-033).
///
/// Spec §5.4.5: "A non-streaming invocation is a stream that emits
/// exactly two chunks: `Data(output)` followed by `End(output)`." This
/// adapter emits ONLY the `Data` half — the framework appends the
/// terminal `End` after the executor returns successfully (so callers
/// using this adapter from inside `exec_*_stream` need not emit `End`
/// themselves).
///
/// Returns silently when the receiver was dropped (cancelled stream) —
/// the framework treats that as the cancellation path and emits a
/// terminal chunk on behalf of the executor.
pub async fn one_shot_to_stream(value: serde_json::Value, tx: &mpsc::Sender<ChunkPayload>) {
    // `Sender::send` returns `Err` only if the receiver was dropped.
    // That happens when the stream was cancelled or the consumer
    // disconnected — in either case the framework's terminal emission
    // path closes the stream, so we silently drop the failed send.
    let _ = tx.send(ChunkPayload::Data { value }).await;
}

// ---------------------------------------------------------------------------
// SCP-OUT-034 streaming dispatch hooks — wires CreditTracker + StreamEscrow
// + CancelAckTracker + StreamAdmissionTracker into the per-chunk pump.
// ---------------------------------------------------------------------------

/// Per-chunk gate result for the SCP-OUT-034 pump.
///
/// Consulted under the shared session lock. `Forward` is the happy
/// path (decrement credit, optionally accrue escrow). `Stall` arms
/// the credit-stall timer. `DropAboveCancelAck` silently drops the
/// chunk per §5.4.5 cancel-ack ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamGateOutcome {
    /// Chunk passes the gate — caller forwards it and advances seq.
    Forward,
    /// Credit exhausted. Caller arms the stall timer and parks the
    /// chunk until a fresh grant arrives.
    Stall,
    /// Cancel-ack ceiling exceeded. Caller drops without billing.
    DropAboveCancelAck,
    /// §5.4.5:758 cumulative billable ceiling reached — the stream has
    /// already emitted `min(credit_window, max_calls)` billable Data
    /// chunks, the HARD upper limit "regardless of executor behavior". A
    /// further billable chunk MUST NOT be forwarded. The pump maps this to
    /// a terminal `Error { terminal: true }` with slug
    /// `execution.credit-exhausted` (`CODE_EXECUTION_CREDIT`,
    /// `SCP-TOOL-6131`) and closes the stream. Distinct from
    /// [`Self::Stall`] (transient — credit may be replenished) and
    /// [`Self::DropAboveCancelAck`] (a single dropped chunk, stream
    /// continues): `CreditExhausted` is terminal.
    CreditExhausted,
}

/// §5.4.5 shared billable-chunk predicate.
///
/// A chunk is billable iff it is a `Data` chunk at or below the cancel-ack
/// billing `ceiling`. Used by BOTH [`apply_stream_chunk_gate`] (the
/// §5.4.5:758 cumulative-ceiling gate) and [`accrue_data_chunk_if_billable`]
/// (escrow accrual) so the two paths can never drift on what counts as a
/// billable chunk.
#[must_use]
pub const fn is_billable_chunk(chunk: &OutletStreamChunk, ceiling: u64) -> bool {
    matches!(chunk.payload, ChunkPayload::Data { .. }) && chunk.sequence <= ceiling
}

/// Applies the SCP-OUT-034 per-chunk gate using the shared session
/// trackers.
///
/// Called from the streaming pump for each upstream chunk. Terminal
/// chunks (`End` / terminal `Error`) bypass the gate. Non-terminal
/// chunks:
///
/// 1. Compare `chunk.sequence` against
///    [`super::stream::CancelAckTracker::billing_ceiling`] —
///    chunks above the ceiling return [`StreamGateOutcome::DropAboveCancelAck`].
/// 2. §5.4.5:758 cumulative ceiling: if the chunk is billable (a `Data`
///    chunk at/below the cancel-ack ceiling) AND the §5.4.5:758
///    cumulative ceiling has already been reached
///    ([`super::stream::CreditTracker::cumulative_ceiling_reached`]),
///    return [`StreamGateOutcome::CreditExhausted`] WITHOUT consuming
///    credit — the HARD `min(credit_window, max_calls)` cap is reached and
///    the stream MUST terminate.
/// 3. Call [`super::stream::CreditTracker::try_consume`]. On
///    [`super::stream::OutOfCredit::Exhausted`], stamp
///    `credit_stall_armed_at` to the current `Instant` and return
///    [`StreamGateOutcome::Stall`].
/// 4. Otherwise return [`StreamGateOutcome::Forward`].
///
/// The function takes a single mutex guard window so the
/// (ceiling → cumulative → consume → bill) decision is atomic with respect
/// to concurrent grant / cancel deliveries on
/// [`super::stream::CreditTracker::grant_with_identity`] /
/// [`super::stream::CancelAckTracker::record_cancel`].
#[must_use]
pub fn apply_stream_chunk_gate(
    credit: &mut super::stream::CreditTracker,
    cancel_ack: &super::stream::CancelAckTracker,
    credit_stall_armed_at: &mut Option<std::time::Instant>,
    chunk: &OutletStreamChunk,
) -> StreamGateOutcome {
    if chunk.payload.is_terminal() {
        return StreamGateOutcome::Forward;
    }
    let ceiling = cancel_ack.billing_ceiling();
    if chunk.sequence > ceiling {
        return StreamGateOutcome::DropAboveCancelAck;
    }
    // §5.4.5:758 cumulative billable ceiling. Only billable (Data,
    // at/below the cancel-ack ceiling) chunks are subject to the
    // `max_calls` cap — Progress chunks below the ceiling still consume
    // credit but are never billed, so they do not count toward the cap.
    // Checked BEFORE `try_consume` so a chunk rejected by the cumulative
    // ceiling does not burn credit.
    if is_billable_chunk(chunk, ceiling) && credit.cumulative_ceiling_reached() {
        return StreamGateOutcome::CreditExhausted;
    }
    if credit.try_consume().is_err() {
        if credit_stall_armed_at.is_none() {
            *credit_stall_armed_at = Some(std::time::Instant::now());
        }
        return StreamGateOutcome::Stall;
    }
    StreamGateOutcome::Forward
}

/// Accrues a Data chunk in the per-stream [`super::stream::StreamEscrow`].
///
/// Bills only when the chunk is billable (a `Data` chunk at or below the
/// cancel-ack ceiling — see [`is_billable_chunk`]). Progress / End / Error
/// chunks and chunks above the ceiling are NOT billed (§5.4.5).
pub const fn accrue_data_chunk_if_billable(
    escrow: &mut super::stream::StreamEscrow,
    cancel_ack: &super::stream::CancelAckTracker,
    chunk: &OutletStreamChunk,
) {
    if is_billable_chunk(chunk, cancel_ack.billing_ceiling()) {
        escrow.accrue_one_chunk();
    }
}

/// Releases the §5.4.5 round-5 admission counters for a stream that
/// terminated. Called by the pump on terminal-chunk emission.
///
/// Decrements per-invoker, per-origin-invoker, and per-outlet counters
/// atomically under the admission tracker's critical section. Idempotent
/// on a never-admitted triple (matches
/// [`super::stream::StreamAdmissionTracker::release`] semantics).
pub fn release_stream_admission(
    admission: &mut super::stream::StreamAdmissionTracker,
    invoker_did: &str,
    origin_invoker_did: &str,
    outlet_id: &str,
) {
    admission.release(invoker_did, origin_invoker_did, outlet_id);
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
    use scp_protocol::context::outlets::OutletKind;
    use scp_protocol::context::outlets::registry::{
        OutletRegistration, OutletSchema, register_outlet,
    };
    use scp_protocol::context::roles::{Capability, CapabilityCeiling, ContextRoleState};

    /// Creates a test capability ceiling with all capabilities.
    fn test_ceiling() -> CapabilityCeiling {
        CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletRegister,
            Capability::OutletCallAll,
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
            &scp_clock::SystemClock,
        )
        .unwrap()
    }

    /// Creates a `ContextRoleState` with an additional member that has limited
    /// capabilities (no `OutletCall`).
    fn test_role_state_with_no_invoke_member(
        creator_did: &str,
        member_did: &str,
    ) -> ContextRoleState {
        let mut state = test_role_state(creator_did);
        state.members.insert(member_did.to_owned());
        // Assign only MessagesRead/Write, no outlet invoke.
        let member_caps: HashSet<Capability> =
            [Capability::MessagesRead, Capability::MessagesWrite]
                .into_iter()
                .collect();
        state
            .member_capabilities
            .insert(member_did.to_owned(), member_caps);
        state
    }

    /// Creates a valid outlet registration and registers it in a fresh registry.
    fn setup_registry_with_outlet(
        role_state: &ContextRoleState,
        registrant_did: &str,
    ) -> OutletRegistry {
        let mut registry = OutletRegistry::new();
        let registration = OutletRegistration {
            outlet_id: "calculator".to_owned(),
            kind: OutletKind::default(),
            name: "Calculator".to_owned(),
            description: "A simple calculator".to_owned(),
            schema: OutletSchema {
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
                aggregate_schema: None,
            },
            implementation_hash: [0xAA; 32],
            test_vectors: vec![],
            operator_did: "did:dht:z6MkOperator".into(),
            cost: None,
            message_catalog: Vec::new(),
            registered_at: 0,
            signature: Vec::new(),
        };
        register_outlet(&mut registry, role_state, registration, registrant_did).unwrap();
        registry
    }

    /// Registers a `calculator` outlet with the given [`OutletKind`] in a fresh
    /// registry — used to prove the kind round-trips and gates invocation.
    fn setup_registry_with_kind(
        role_state: &ContextRoleState,
        registrant_did: &str,
        kind: OutletKind,
    ) -> OutletRegistry {
        let mut registry = OutletRegistry::new();
        let registration = OutletRegistration {
            outlet_id: "calculator".to_owned(),
            kind,
            name: "Calculator".to_owned(),
            description: "A simple calculator".to_owned(),
            schema: OutletSchema {
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
                aggregate_schema: None,
            },
            implementation_hash: [0xAA; 32],
            test_vectors: vec![],
            operator_did: "did:dht:z6MkOperator".into(),
            cost: None,
            message_catalog: Vec::new(),
            registered_at: 0,
            signature: Vec::new(),
        };
        register_outlet(&mut registry, role_state, registration, registrant_did).unwrap();
        // The registered kind must round-trip through the registry — this is
        // what the invoke gate and the UCAN stem selection read back.
        assert_eq!(registry.get("calculator").unwrap().kind, kind);
        registry
    }

    /// Creates an active context handle (transitions from Creating to Active).
    fn active_context() -> ContextHandle {
        let handle = ContextHandle::new("ctx-invoke-test".to_owned(), ContextParams::default());
        handle.transition_to(&ContextState::Active).unwrap();
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
    // invoke_outlet: happy path
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_succeeds_with_valid_invocation() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();

        let input = serde_json::json!({"a": 3, "b": 4});
        let result = invoke_outlet(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            input,
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
        )
        .await;

        assert!(result.is_ok(), "invoke_outlet should succeed: {result:?}");
        let (output, event, _consequences, _receipt) = result.unwrap();
        assert_eq!(output, serde_json::json!({"result": 7.0}));
        assert_eq!(event.outlet_id, "calculator");
        assert_eq!(event.invoker_did, creator_did);
        assert_eq!(event.status, OutletStatus::Success);
        assert!(event.output_hash.is_some());
        assert!(!event.input_hash.is_empty());
    }

    // -----------------------------------------------------------------------
    // invoke_outlet: context not Active
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_rejects_when_context_not_active() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);

        // Context is in Creating state (not Active).
        let context = ContextHandle::new("ctx-test".to_owned(), ContextParams::default());

        let result = invoke_outlet(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
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
    // invoke_outlet: invoker without OutletCall capability
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_rejects_invoker_without_outlet_invoke_capability() {
        let creator_did = "did:dht:z6MkCreator";
        let member_did = "did:dht:z6MkMember";
        let role_state = test_role_state_with_no_invoke_member(creator_did, member_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();

        let result = invoke_outlet(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
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
    // invoke_outlet: outlet not found
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_rejects_unknown_outlet() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = OutletRegistry::new(); // Empty registry
        let context = active_context();

        let result = invoke_outlet(
            &context,
            &registry,
            &role_state,
            &"nonexistent-outlet".to_owned(),
            serde_json::json!({}),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::OutletNotFound { .. }),
            "expected OutletNotFound, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_outlet: input schema validation failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_rejects_invalid_input_schema() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();

        // Input schema expects an object, passing a string instead.
        let result = invoke_outlet(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!("not an object"),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
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
    // invoke_outlet: timeout
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_timeout_synthesizes_timeout_error() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();

        // Executor that sleeps for 5 seconds (will be timed out).
        let slow_executor = |_input: serde_json::Value| async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(serde_json::json!({"result": 42}))
        };

        let result = invoke_outlet(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            Some(50), // 50ms timeout -- will expire before the 5s sleep.
            slow_executor,
            None::<&mut OutletEconomyContext<'_>>,
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
    // invoke_outlet: cancellation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_cancellation_returns_cancelled_status() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();

        // Executor that sleeps for 5 seconds (will be cancelled).
        let slow_executor = |_input: serde_json::Value| async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(serde_json::json!({"result": 42}))
        };

        // Cancellation fires after 10ms.
        let cancel = || async {
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        let result = invoke_outlet_with_cancellation(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            slow_executor,
            cancel,
            None::<&mut OutletEconomyContext<'_>>,
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
    // invoke_outlet: execution failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_execution_failure_propagates_error() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();

        // Executor that always fails.
        let failing_executor = |_input: serde_json::Value| async {
            Err::<serde_json::Value, String>("computation exploded".to_owned())
        };

        let result = invoke_outlet(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            failing_executor,
            None::<&mut OutletEconomyContext<'_>>,
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
    // invoke_outlet: output schema validation failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_rejects_invalid_output_schema() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();

        // Executor that returns a string instead of an object.
        let bad_output_executor = |_input: serde_json::Value| async {
            Ok::<serde_json::Value, String>(serde_json::json!("not an object"))
        };

        let result = invoke_outlet(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            bad_output_executor,
            None::<&mut OutletEconomyContext<'_>>,
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
    // invoke_outlet: event log records hashes, not full data
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_event_contains_hashes_not_full_data() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();

        let input = serde_json::json!({"a": 10, "b": 20});

        let (output, event, _consequences, _receipt) = invoke_outlet(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            input.clone(),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
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
    // invoke_outlet: context in Closing state
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_rejects_closing_context() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);

        let context = ContextHandle::new("ctx-closing".to_owned(), ContextParams::default());
        context.transition_to(&ContextState::Active).unwrap();
        context.transition_to(&ContextState::Closing).unwrap();

        let result = invoke_outlet(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            InvocationError::ContextNotActive { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // has_outlet_call_capability
    // -----------------------------------------------------------------------

    #[test]
    fn has_outlet_call_capability_returns_true_for_invoke_all() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        assert!(has_outlet_call_capability(
            &role_state,
            "did:dht:z6MkCreator",
            "any-outlet"
        ));
    }

    #[test]
    fn has_outlet_call_capability_returns_false_without_capability() {
        let role_state =
            test_role_state_with_no_invoke_member("did:dht:z6MkCreator", "did:dht:z6MkMember");
        assert!(!has_outlet_call_capability(
            &role_state,
            "did:dht:z6MkMember",
            "calculator"
        ));
    }

    #[test]
    fn has_outlet_call_capability_with_specific_outlet() {
        let mut role_state =
            test_role_state_with_no_invoke_member("did:dht:z6MkCreator", "did:dht:z6MkMember");
        // Add specific OutletCall capability.
        role_state
            .member_capabilities
            .get_mut("did:dht:z6MkMember")
            .unwrap()
            .insert(Capability::OutletCall("calculator".to_owned()));

        assert!(has_outlet_call_capability(
            &role_state,
            "did:dht:z6MkMember",
            "calculator"
        ));
        // But not for a different outlet.
        assert!(!has_outlet_call_capability(
            &role_state,
            "did:dht:z6MkMember",
            "other-outlet"
        ));
    }

    // -----------------------------------------------------------------------
    // has_outlet_invocation_capability — kind-aware split-capability gate
    // (SCP-OUT-014, spec §5.4.2). The two stems are INDEPENDENT: a Query
    // outlet cannot be invoked with an Action (OutletCall) grant and vice
    // versa. This is the defense-in-depth mirror of the UCAN stem selection.
    // -----------------------------------------------------------------------

    /// A Query outlet requires `OutletQuery` — an `OutletCall` grant (Action
    /// class) does NOT authorize it.
    #[test]
    fn query_outlet_denies_call_capability_allows_query_capability() {
        let creator = "did:dht:z6MkCreator";
        let member = "did:dht:z6MkMember";
        let mut role_state = test_role_state_with_no_invoke_member(creator, member);
        // Member holds ONLY the Action-class OutletCall grant.
        role_state
            .member_capabilities
            .get_mut(member)
            .unwrap()
            .insert(Capability::OutletCall("calculator".to_owned()));
        assert!(
            !has_outlet_invocation_capability(&role_state, member, "calculator", OutletKind::Query),
            "OutletCall must NOT authorize a Query-class invocation"
        );
        // Granting the Query-class capability authorizes it.
        role_state
            .member_capabilities
            .get_mut(member)
            .unwrap()
            .insert(Capability::OutletQuery("calculator".to_owned()));
        assert!(
            has_outlet_invocation_capability(&role_state, member, "calculator", OutletKind::Query),
            "OutletQuery must authorize a Query-class invocation"
        );
    }

    /// An Action outlet requires `OutletCall` — an `OutletQuery` grant (Query
    /// class) does NOT authorize it.
    #[test]
    fn action_outlet_denies_query_capability_allows_call_capability() {
        let creator = "did:dht:z6MkCreator";
        let member = "did:dht:z6MkMember";
        let mut role_state = test_role_state_with_no_invoke_member(creator, member);
        // Member holds ONLY the Query-class OutletQuery grant.
        role_state
            .member_capabilities
            .get_mut(member)
            .unwrap()
            .insert(Capability::OutletQuery("calculator".to_owned()));
        assert!(
            !has_outlet_invocation_capability(
                &role_state,
                member,
                "calculator",
                OutletKind::Action
            ),
            "OutletQuery must NOT authorize an Action-class invocation"
        );
        role_state
            .member_capabilities
            .get_mut(member)
            .unwrap()
            .insert(Capability::OutletCall("calculator".to_owned()));
        assert!(
            has_outlet_invocation_capability(&role_state, member, "calculator", OutletKind::Action),
            "OutletCall must authorize an Action-class invocation"
        );
    }

    /// The wildcard grants are independent too: `OutletCallAll` authorizes any
    /// Action but no Query; `OutletQueryAll` authorizes any Query but no Action.
    #[test]
    fn wildcard_call_and_query_grants_are_independent() {
        let creator = "did:dht:z6MkCreator";
        let member = "did:dht:z6MkMember";

        let mut with_call_all = test_role_state_with_no_invoke_member(creator, member);
        with_call_all
            .member_capabilities
            .get_mut(member)
            .unwrap()
            .insert(Capability::OutletCallAll);
        assert!(has_outlet_invocation_capability(
            &with_call_all,
            member,
            "anything",
            OutletKind::Action
        ));
        assert!(
            !has_outlet_invocation_capability(
                &with_call_all,
                member,
                "anything",
                OutletKind::Query
            ),
            "OutletCallAll must NOT authorize a Query invocation"
        );

        let mut with_query_all = test_role_state_with_no_invoke_member(creator, member);
        with_query_all
            .member_capabilities
            .get_mut(member)
            .unwrap()
            .insert(Capability::OutletQueryAll);
        assert!(has_outlet_invocation_capability(
            &with_query_all,
            member,
            "anything",
            OutletKind::Query
        ));
        assert!(
            !has_outlet_invocation_capability(
                &with_query_all,
                member,
                "anything",
                OutletKind::Action
            ),
            "OutletQueryAll must NOT authorize an Action invocation"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_outlet: timeout is clamped to protocol maximum
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_clamps_timeout_to_protocol_maximum() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();

        // Request a timeout larger than the protocol max.
        // The executor completes immediately, so the test verifies the function
        // does not error out due to an absurdly large timeout.
        let result = invoke_outlet(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            Some(999_999), // Above MAX_TIMEOUT_MS
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
        )
        .await;

        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // invoke_outlet: end-to-end query-capability gate (SCP-OUT-014). Proves the
    // OutletQuery path actually works: a Query outlet is DENIED with only
    // OutletCall and ALLOWED with OutletQuery. Symmetric guard for Action.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_query_outlet_denied_with_call_cap_allowed_with_query_cap() {
        let creator = "did:dht:z6MkCreator";
        let member = "did:dht:z6MkMember";

        // Creator (admin) registers a QUERY-kind outlet; kind round-trips.
        let mut role_state = test_role_state(creator);
        role_state.members.insert(member.to_owned());
        let registry = setup_registry_with_kind(&role_state, creator, OutletKind::Query);
        let context = active_context();

        // Member holds ONLY the Action-class OutletCall grant → DENIED, because
        // the outlet is registered as Query and the two stems are independent.
        role_state.member_capabilities.insert(
            member.to_owned(),
            std::iter::once(Capability::OutletCall("calculator".to_owned())).collect(),
        );
        let denied = invoke_outlet(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
        )
        .await;
        assert!(
            matches!(
                denied.unwrap_err(),
                InvocationError::InvokerNotAuthorized { .. }
            ),
            "Query outlet must be denied to a member holding only OutletCall"
        );

        // Grant the Query-class capability → ALLOWED.
        role_state
            .member_capabilities
            .get_mut(member)
            .unwrap()
            .insert(Capability::OutletQuery("calculator".to_owned()));
        let allowed = invoke_outlet(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
        )
        .await;
        assert!(
            allowed.is_ok(),
            "Query outlet must be allowed once the member holds OutletQuery: {:?}",
            allowed.err()
        );
    }

    #[tokio::test]
    async fn invoke_action_outlet_denied_with_query_cap_allowed_with_call_cap() {
        let creator = "did:dht:z6MkCreator";
        let member = "did:dht:z6MkMember";

        let mut role_state = test_role_state(creator);
        role_state.members.insert(member.to_owned());
        // ACTION-kind outlet.
        let registry = setup_registry_with_kind(&role_state, creator, OutletKind::Action);
        let context = active_context();

        // Member holds ONLY the Query-class grant → DENIED for an Action outlet.
        role_state.member_capabilities.insert(
            member.to_owned(),
            std::iter::once(Capability::OutletQuery("calculator".to_owned())).collect(),
        );
        let denied = invoke_outlet(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
        )
        .await;
        assert!(
            matches!(
                denied.unwrap_err(),
                InvocationError::InvokerNotAuthorized { .. }
            ),
            "Action outlet must be denied to a member holding only OutletQuery"
        );

        // Grant the Action-class capability → ALLOWED.
        role_state
            .member_capabilities
            .get_mut(member)
            .unwrap()
            .insert(Capability::OutletCall("calculator".to_owned()));
        let allowed = invoke_outlet(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
        )
        .await;
        assert!(
            allowed.is_ok(),
            "Action outlet must be allowed once the member holds OutletCall: {:?}",
            allowed.err()
        );
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
            outlet_id: "outlet-1".to_owned(),
        };
        assert!(err.to_string().contains("did:dht:test"));
        assert!(err.to_string().contains("outlet-1"));

        let err = InvocationError::OutletNotFound {
            outlet_id: "missing".to_owned(),
        };
        assert!(err.to_string().contains("missing"));

        let err = InvocationError::Timeout { timeout_ms: 5000 };
        assert!(err.to_string().contains("5000"));

        let err = InvocationError::Cancelled;
        assert!(err.to_string().contains("cancelled"));
    }

    // -----------------------------------------------------------------------
    // validate_outlet_invocation_ucan: rejects non-outlet capability (#319)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_outlet_invocation_ucan_rejects_non_outlet_capability() {
        use crate::crypto::ucan::mint::{MintParams, mint_ucan};
        use scp_platform::testing::InMemoryKeyCustody;
        use scp_platform::traits::{KeyCustody, KeyType};
        use scp_protocol::crypto::ucan::validate::{
            DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, InMemoryDidResolver, InMemoryNonceTracker,
            InMemoryProofResolver, InMemoryRevocationChecker, NoCaveatResolver, ValidationContext,
        };

        // Set up issuer identity.
        let custody = InMemoryKeyCustody::new();
        let key_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&key_handle).await.unwrap();
        let pk_bytes: [u8; 32] = pubkey.as_bytes().try_into().unwrap();
        let issuer_did = format!("did:dht:z{}", zbase32::encode(pubkey.as_bytes()));

        // Mint a UCAN with messages:write capability (NOT outlet_call).
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
        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
            "outlet_call:calculator".to_owned(),
        ]
        .into_iter()
        .collect();

        let caveat_resolver = NoCaveatResolver;
        let mut ctx = ValidationContext {
            did_resolver: &resolver,
            nonce_tracker: &mut nonce_tracker,
            revocation_checker: &revocation_checker,
            proof_resolver: &proof_resolver,
            caveat_resolver: &caveat_resolver,
            ceiling: &ceiling,
            context_creator_did: &issuer_did,
            presenting_agent_did: "did:dht:z6MkMember",
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            clock: &scp_clock::SystemClock,
        };

        // validate_outlet_invocation_ucan expects outlet_call:calculator
        // (Action kind), but the token only has messages:write — must be
        // rejected.
        let result = validate_outlet_invocation_ucan(
            &token.encoded,
            "ctx-test",
            "calculator",
            OutletKind::Action,
            &mut ctx,
        );

        assert!(
            result.is_err(),
            "UCAN with messages:write must be rejected for outlet invocation"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, UcanError::CapabilityNotGranted(..)),
            "expected CapabilityNotGranted, got {err:?}"
        );
    }

    /// SCP-OUT-014 primary gate: `validate_outlet_invocation_ucan` selects the
    /// capability stem from the outlet's registered kind. A token carrying only
    /// `outlet_call:calculator` must be REJECTED for a Query outlet and ACCEPTED
    /// for an Action outlet; a token carrying only `outlet_query:calculator`
    /// must be ACCEPTED for a Query outlet and REJECTED for an Action outlet.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // two token mints + four validation assertions
    async fn validate_outlet_invocation_ucan_selects_stem_by_kind() {
        use crate::crypto::ucan::mint::{MintParams, mint_ucan};
        use scp_platform::testing::InMemoryKeyCustody;
        use scp_platform::traits::{KeyCustody, KeyType};
        use scp_protocol::crypto::ucan::validate::{
            DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, InMemoryDidResolver, InMemoryNonceTracker,
            InMemoryProofResolver, InMemoryRevocationChecker, NoCaveatResolver, ValidationContext,
        };

        let custody = InMemoryKeyCustody::new();
        let key_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&key_handle).await.unwrap();
        let pk_bytes: [u8; 32] = pubkey.as_bytes().try_into().unwrap();
        let issuer_did = format!("did:dht:z{}", zbase32::encode(pubkey.as_bytes()));

        // Mint two tokens: one with the Action stem, one with the Query stem.
        let call_caps = vec!["outlet_call:calculator".to_owned()];
        let call_params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-test",
            capabilities: &call_caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };
        let call_token = mint_ucan(&call_params, &custody, &scp_clock::SystemClock)
            .await
            .unwrap();

        let query_caps = vec!["outlet_query:calculator".to_owned()];
        let query_params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-test",
            capabilities: &query_caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };
        let query_token = mint_ucan(&query_params, &custody, &scp_clock::SystemClock)
            .await
            .unwrap();

        let ceiling: HashSet<String> = [
            "outlet_call:calculator".to_owned(),
            "outlet_query:calculator".to_owned(),
        ]
        .into_iter()
        .collect();

        // Helper that validates a token against a given outlet kind. A fresh
        // nonce tracker per call avoids single-use nonce rejections.
        let validate = |encoded: String, kind: OutletKind| {
            let resolver = InMemoryDidResolver {
                keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
                kid_keys: std::collections::HashMap::new(),
            };
            let ceiling = ceiling.clone();
            let issuer_did = issuer_did.clone();
            async move {
                let mut nonce_tracker = InMemoryNonceTracker::new();
                let revocation_checker = InMemoryRevocationChecker::new();
                let proof_resolver = InMemoryProofResolver::new();
                let caveat_resolver = NoCaveatResolver;
                let mut ctx = ValidationContext {
                    did_resolver: &resolver,
                    nonce_tracker: &mut nonce_tracker,
                    revocation_checker: &revocation_checker,
                    proof_resolver: &proof_resolver,
                    caveat_resolver: &caveat_resolver,
                    ceiling: &ceiling,
                    context_creator_did: &issuer_did,
                    presenting_agent_did: "did:dht:z6MkMember",
                    clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
                    clock: &scp_clock::SystemClock,
                };
                validate_outlet_invocation_ucan(&encoded, "ctx-test", "calculator", kind, &mut ctx)
            }
        };

        // Action token: accepted for Action, rejected for Query.
        assert!(
            validate(call_token.encoded.clone(), OutletKind::Action)
                .await
                .is_ok(),
            "outlet_call token must satisfy an Action outlet"
        );
        assert!(
            matches!(
                validate(call_token.encoded.clone(), OutletKind::Query).await,
                Err(UcanError::CapabilityNotGranted(..))
            ),
            "outlet_call token must NOT satisfy a Query outlet"
        );

        // Query token: accepted for Query, rejected for Action.
        assert!(
            validate(query_token.encoded.clone(), OutletKind::Query)
                .await
                .is_ok(),
            "outlet_query token must satisfy a Query outlet"
        );
        assert!(
            matches!(
                validate(query_token.encoded.clone(), OutletKind::Action).await,
                Err(UcanError::CapabilityNotGranted(..))
            ),
            "outlet_query token must NOT satisfy an Action outlet"
        );
    }

    // budget_exceeded on outlet invocation returns BudgetExceeded
    #[tokio::test]
    async fn budget_exceeded_outlet_invoke() {
        use scp_protocol::economy::types::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};

        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: CurrencyCode::new([85, 83, 68, 0]),
                per_message: None,
                per_outlet_call: Some(Amount::new(200)),
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
        // Grant only 100 budget but outlet costs 200.
        tracker.grant(&invoker, Amount::new(100));

        // Budget enforcement is now inline in economy_pre_check via invoke_outlet.
        // Test it through invoke_outlet with a OutletEconomyContext.
        let context = active_context();
        let role_state = test_role_state(invoker.as_ref());
        let registry = setup_registry_with_outlet(&role_state, invoker.as_ref());
        // Test fixture metrics: zeros are intentional for this budget-
        // exhaustion test. The test asserts budget-cap behaviour in
        // isolation and does NOT exercise §19.7 per-DID velocity
        // escalation — that behaviour is covered end-to-end by the
        // `invoke_outlet_with_economy` wrapper on `ContextManager` which
        // populates `sender_velocity` from the live velocity tracker via
        // `velocity_tracker.get_velocity(invoker_did, now_secs)` at
        // `crates/scp-runtime/src/context/manager/outlets.rs` (see the
        // `invoke_outlet_with_economy_wires_escalation_and_rollback` and
        // `invoke_outlet_with_economy_releases_lock_before_executor`
        // structural assertions in
        // `crates/scp-testing/tests/integration/pipeline_wiring.rs` which
        // pin the real wiring, and the behavioural escalation test in
        // `crates/scp-runtime/src/context/manager/tests/messaging.rs`).
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
                time_window: std::time::Duration::from_hours(24),
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
                    nb: None,
                },
                signature: vec![0u8; 64],
                encoded: String::new(),
            }
        };
        let mut economy = super::OutletEconomyContext {
            economic_policy: Some(&policy),
            budget_tracker: &mut tracker,
            spending_ucan: Some(&spending_ucan),
            context_id: "ctx-invoke-test",
            now: 0,
            events: &[],
            convergent_now: 0,
            participation_cache: &mut participation,
            consequence_rules: &[],
            payment_adapter: None,
            metrics,
            velocity_tracker: None,
            message_pricing: None,
        };

        let result = super::invoke_outlet(
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
