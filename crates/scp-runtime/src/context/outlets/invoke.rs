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
use std::panic::AssertUnwindSafe;
use std::time::Duration;

use futures::FutureExt;
use tokio::sync::mpsc;

use crate::context::ContextHandle;
use scp_did::DID;
use scp_protocol::context::ContextState;
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::error_codes::{
    CODE_EXECUTION_FAULT, SLUG_EXECUTION_HANDLER_PANIC, SLUG_EXECUTION_TIMEOUT,
};
use scp_protocol::context::outlets::errors::MESSAGE_MAX_BYTES;
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

    /// A Query outlet's declared cost violated the §5.4.2 Query cost rules.
    ///
    /// Error code: `SCP-OUTLET-6100` (the registry maps the
    /// `query-cost-violation` slug to `CODE_PROTOCOL_VIOLATION`; the
    /// registry is truth).
    #[error("Query outlet cost violation (§5.4.2): {reason}")]
    OutletQueryCostViolation {
        /// Human-readable reason — which sub-rule was violated.
        reason: String,
    },

    /// A Query outlet's executor attempted a write through `MutableInvocation`
    /// (or otherwise tripped the [`ReadOnlyInvocation`] deny-list), per spec
    /// §5.4.2 "`ReadOnlyInvocation` guard at invocation" (SCP-OUT-013).
    ///
    /// Maps to `OutletErrorClass::Protocol::QueryViolation` (SCP-OUTLET-6100,
    /// slug `query-violation`) and triggers an
    /// `OutletVerifiedEvent { integrity_ok: false, reason:
    /// QueryMisdeclaration }` operator-attributable signal per §5.4.2.
    #[error(
        "Query outlet \"{outlet_id}\" attempted write \"{operation}\" through ReadOnlyInvocation (§5.4.2)"
    )]
    QueryViolation {
        /// The outlet that mis-declared as Query.
        outlet_id: String,
        /// The denied operation (e.g., `"send_message"`, `"register_outlet"`).
        operation: &'static str,
    },

    /// The dispatched [`OutletExecutor`] half does not match the registered
    /// outlet kind — the executor's `exec_query`/`exec_action` default impl
    /// returned [`OutletExecutorError::KindMismatch`] (SCP-OUT-013 AC4).
    #[error(
        "outlet \"{outlet_id}\" registered as {kind:?} but executor returned KindMismatch (§5.4.2)"
    )]
    KindMismatch {
        /// The outlet whose dispatched executor half was missing.
        outlet_id: String,
        /// The registered kind that drove dispatch.
        kind: scp_protocol::context::outlets::OutletKind,
    },

    /// The outlet's executor panicked inside `exec_query` / `exec_action`
    /// (SCP-OUT-028).
    ///
    /// Recovered by the [`std::panic::catch_unwind`] guard the runtime
    /// applies around every executor call (ADR-049 §148). Per spec §5.4.2 /
    /// §5.4.4, panics are protocol-visible signals attributable to the
    /// outlet's `operator_did` — not SDK-internal bugs. The runtime emits a
    /// parallel `OutletVerifiedEvent { integrity_ok: false, reason:
    /// HandlerPanicked }` alongside this error. On the wire this maps to
    /// `OutletError { code: SCP-OUTLET-6130, slug: "execution.handler-panic",
    /// class: Execution, retry: Never, ... }`. The `panic_message` is
    /// truncated to `MESSAGE_MAX_BYTES` (1 KiB) at a UTF-8 boundary.
    #[error(
        "outlet \"{outlet_id}\" handler panicked ({code}, {slug}): {panic_message}",
        code = scp_protocol::context::outlets::error_codes::CODE_EXECUTION_FAULT,
        slug = scp_protocol::context::outlets::error_codes::SLUG_EXECUTION_HANDLER_PANIC,
    )]
    HandlerPanic {
        /// The outlet whose executor panicked.
        outlet_id: String,
        /// Stringified panic payload, truncated to `MESSAGE_MAX_BYTES`
        /// bytes at a UTF-8 boundary. `"<unknown panic payload>"` when the
        /// payload is neither `&'static str` nor `String`.
        panic_message: String,
    },

    /// A best-effort cross-context stream open
    /// ([`invoke_outlet_cross_context`]) targeted a **paid** Action outlet
    /// (`cost.is_some() && cost.amount > 0`).
    ///
    /// The best-effort cross-context bridge is **zero-escrow** (spec §5.4.5
    /// "Cross-context economy (best-effort is zero-escrow)"): it serves Query
    /// outlets and zero-cost (`cost == None || cost.amount == 0`) Action
    /// outlets only, propagating the invoker's credit grants end-to-end as
    /// backpressure — credit is flow-control, not payment — and performs **no
    /// caller-side escrow settlement**. Per ADR-061 caller-side escrow
    /// settlement is **saga-unique**, so a metered, paid cross-context stream
    /// MUST use the **streaming saga** (§6.2.4 / §6.2.5; SCP-OUT-046).
    ///
    /// This is an **open-time economic/authorization-class rejection**
    /// returned as `Err(InvocationError)` **before any stream or receiver is
    /// created** — NOT a terminal chunk, and NOT a transport fault. It is
    /// therefore never routed through the terminal-chunk path and must not be
    /// mapped to the Transport code (`SCP-OUTLET-6160`).
    #[error(
        "outlet \"{outlet_id}\" is a paid Action outlet; the best-effort cross-context bridge is zero-escrow (§5.4.5) — a metered paid cross-context stream must use the streaming saga (SCP-OUT-046)"
    )]
    CrossContextPaidActionUnsupported {
        /// The paid Action outlet the best-effort cross-context open rejected.
        outlet_id: String,
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
pub async fn invoke_outlet_aggregating<F, Fut, S: BuildHasher>(
    context: &ContextHandle,
    registry: &OutletRegistry,
    role_state: &ContextRoleState,
    outlet_id: &OutletId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: F,
    mut economy: Option<&mut OutletEconomyContext<'_, S>>,
    handler_panic_sink: Option<&dyn HandlerPanicSink>,
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
    // wrapper can share the exact same execution path. SCP-OUT-028: the helper
    // applies the `catch_unwind` panic guard internally and forwards
    // `handler_panic_sink` for OutletVerified attribution.
    let outcome = match invoke_outlet_execute_and_validate(
        context,
        registry,
        role_state,
        outlet_id,
        input,
        invoker_did,
        timeout_ms,
        executor,
        handler_panic_sink,
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
    handler_panic_sink: Option<&dyn HandlerPanicSink>,
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
    //
    // SCP-OUT-028: the executor closure + future are wrapped in
    // `catch_unwind` via `run_executor_with_panic_guard`. A panic in
    // `exec_query`/`exec_action` is recovered into
    // `InvocationError::HandlerPanic` and emits the §5.4.2 parallel
    // `OutletVerifiedEvent { reason: HandlerPanicked }` through
    // `handler_panic_sink` — the panic does not escape `invoke_outlet`.
    let effective_timeout = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS).min(MAX_TIMEOUT_MS);
    let timeout_duration = Duration::from_millis(u64::from(effective_timeout));
    let guarded = run_executor_with_panic_guard(executor, input, outlet_id, handler_panic_sink);
    let execution_result = tokio::time::timeout(timeout_duration, guarded).await;
    let output = match execution_result {
        Ok(Ok(Ok(output))) => output,
        Ok(Ok(Err(exec_err))) => {
            return Err(InvocationError::ExecutionFailed { message: exec_err });
        }
        Ok(Err(panic_err)) => {
            // The panic guard already emitted the warn-level log and the
            // `OutletVerified` signal; surface the typed envelope.
            return Err(panic_err);
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
        // Unary "plain outlet invocation" per ADR-061: commits `output_hash`
        // and is NOT modeled as a stream (distinct delivery mode, not a
        // degenerate one-chunk stream). No chunks are produced, so the
        // streaming event fields take their no-manifest sentinels — identical
        // to the `#[serde(default …)]` values lifecycle.rs uses for events that
        // pre-date the streaming taxonomy. No streaming behavior is introduced
        // here; this is a shape reconcile only.
        stream_chunk_count: 0,
        chunks_billed: 0,
        stream_manifest_hash: [0u8; 32],
        stream_terminal_status: StreamTerminalStatus::Ok,
        cancel_ack_seq: None,
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
pub async fn invoke_outlet_with_cancellation_aggregating<F, Fut, C, CFut, S: BuildHasher>(
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
    ///
    /// A durable sink persists the event through
    /// [`ContextEventLogProvider::append_event`](crate::context::builder::ContextEventLogProvider::append_event),
    /// whose override re-runs the durable event-local
    /// `chunks_billed <= stream_chunk_count` backstop
    /// ([`verify_outlet_invoked_event_local`](super::stream::verify_outlet_invoked_event_local)).
    /// Same-context billing integrity is enforced INLINE in the pump before this
    /// call (`AuditAnomaly::ChunksBilledSelfMismatch`), not re-derived here: the
    /// pump does not retain the payload set, so the full §5.4.5:566 manifest
    /// re-derivation applies only on the Sequence path (cross-context reassembly
    /// / import, slice 3).
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

/// Durable crash-recovery record for an in-flight streaming reservation.
///
/// Fix-D — the streaming analogue of the §6.2.4
/// [`CallerReservationRecord`](crate::context::supervisor::saga_prepared_state::CallerReservationRecord).
///
/// **Why this exists.** A streaming open makes TWO durable reservations that
/// the close-time settlement is responsible for releasing: (1) the §5.4.5
/// open-time escrow HOLD debited against the invoker's `MemberBudgetTracker`,
/// and (2) the §7.3.8 `AmountCumulative` counter reserve committed at the
/// pump's open-time final gate. The pump runs as a SEPARATE `tokio` task that
/// SURVIVES an actor crash + respawn (generation `G → G+1`). On crash-restore
/// the pump's close-time settlement lands with the pre-crash generation `G`,
/// mismatches the respawned `G+1`, and the confused-deputy guard DROPS it — so
/// without this record the durable escrow debit and cumulative counter reserve
/// (both restored in the ADR-049 §9 snapshot) would NEVER be released: a
/// permanent over-charge + a cumulative-cap capacity leak. The generation guard
/// alone cannot distinguish an import-REPLACE (where the whole state was
/// swapped, so a drop is correct) from a crash-RESTORE (where the reserves are
/// this same context's own restored state and MUST be released).
///
/// **Lifetime — persisted once, cleared once.** The record is persisted
/// atomically at pump open (after BOTH reservations are durable — the counter
/// reserve is the later of the two), keyed by the stream `request_id`. It is
/// cleared on the clean close-time settlement (generation match → release /
/// refund / clear in one Class-S commit). Its ONLY surviving path is a crash
/// while the pump is mid-flight — exactly the leak above — which the restore-
/// time [`ReconcileStreamReservations`](crate::context::actor::commands::OutletsCommand::ReconcileStreamReservations)
/// sweep drains: refund the full `reserved_escrow` + release the full
/// `amount_cumulative_reserved`, then clear.
///
/// **Class S** — synchronously persisted fail-closed (ADR-049 §9) so a crash in
/// the coalesce window cannot lose the only durable handle for reserves that DID
/// persist. Survives same-node restore; dropped on cross-node export/import
/// (the invoker economy + counters are local — a foreign node must never drive
/// a local release), exactly like `xctx_caller_reservations` / `caveat_counters`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StreamReservationRecord {
    /// The invoker whose budget hold (`reserved_escrow`) the crash-recovery
    /// sweep refunds via `MemberBudgetTracker::reverse_spend`.
    pub invoker_did: DID,
    /// The opening UCAN CID — the key of the §7.3.8 `AmountCumulative` counter
    /// the sweep releases `amount_cumulative_reserved` back to. Empty when no
    /// counter-bearing cap was reserved (escrow-only stream).
    pub ucan_cid: String,
    /// The per-billable-chunk cost at open (diagnostics / provenance — the
    /// sweep releases the FULL reserved amounts since the billed count is
    /// unknown once the pump is gone).
    pub cost_per_chunk: scp_protocol::economy::types::Amount,
    /// The worst-case cumulative amount reserved against the `AmountCumulative`
    /// counter at open (`0` when no cap / no store / zero-cost). Released in
    /// full by the crash-recovery sweep.
    pub amount_cumulative_reserved: u64,
    /// The §5.4.5 open-time escrow hold debited against the invoker's budget
    /// tracker (`0` for zero-cost / Query streams). Refunded in full by the
    /// crash-recovery sweep.
    pub reserved_escrow: scp_protocol::economy::types::Amount,
    /// The actor spawn-`generation` the reservation was made against
    /// (diagnostics only — the crash-recovery sweep reconciles the restored
    /// context's OWN reserves regardless of generation, since a restore
    /// overwrites `PerContextState::generation` with a fresh spawn generation).
    pub generation: u64,
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

    /// Fix-D — durably persist the crash-recovery
    /// [`StreamReservationRecord`] at pump open, AFTER both open-time
    /// reservations (the §5.4.5 escrow hold + the §7.3.8 cumulative counter
    /// reserve) are durable, keyed by the stream `request_id`. Unlike
    /// [`settle`](Self::settle) this is AWAITED on the open path so the record
    /// is durable before the pump bills — a crash mid-stream is then
    /// reconciled at restore. The implementation stamps the record's
    /// `generation` with the reservation's spawn-generation. Returns the
    /// persist / transport infrastructure outcome. Dyn-safe boxed future (the
    /// concrete impl routes onto the actor mailbox), mirroring
    /// [`CaveatCounterApi`](crate::trust::CaveatCounterApi).
    fn persist_reservation<'a>(
        &'a self,
        context_id: &str,
        request_id: RequestId,
        record: StreamReservationRecord,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), scp_protocol::context::ContextError>>
                + Send
                + 'a,
        >,
    >;
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
/// the credit-stall timer. `DropAboveCancelAck` silently drops a
/// non-terminal chunk at OR above the cancel-ack sequence (§5.4.5:530 —
/// the cancel-ack slot belongs to the terminal chunk).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamGateOutcome {
    /// Chunk passes the gate — caller forwards it and advances seq.
    Forward,
    /// Credit exhausted. Caller arms the stall timer and parks the
    /// chunk until a fresh grant arrives.
    Stall,
    /// Non-terminal chunk at or above the cancel-ack sequence. Caller
    /// drops it without billing or advancing the emission cursor, so the
    /// terminal cancel-ack chunk lands on `cancel_ack_seq` (§5.4.5:530(3)).
    DropAboveCancelAck,
    /// §5.4.5:758 cumulative billable ceiling reached — the stream has
    /// already emitted `min(credit_window, max_calls)` billable Data
    /// chunks, the HARD upper limit "regardless of executor behavior". A
    /// further billable chunk MUST NOT be forwarded. The pump maps this to
    /// a terminal `Error { terminal: true }` with slug
    /// `execution.credit-exhausted` (`CODE_EXECUTION_CREDIT`,
    /// `SCP-OUTLET-6131`) and closes the stream. Distinct from
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
///    [`super::stream::CancelAckTracker::billing_ceiling`] — non-terminal
///    chunks at OR above the cancel-ack sequence return
///    [`StreamGateOutcome::DropAboveCancelAck`]. The boundary is `>=`, not
///    `>`, because §5.4.5:530(3) reserves the cancel-ack sequence slot for
///    the terminal cancel-ack chunk: after a cancel, `cancel_ack_seq` is the
///    next-to-emit cursor, the framework's terminal chunk takes exactly that
///    sequence, and any in-flight `Data`/`Progress` the executor emits at
///    `sequence >= cancel_ack_seq` is dropped-and-not-billed (§5.4.5:530(1)
///    "chunks already in flight at that sequence are NOT counted as
///    billable"). An uncancelled stream's ceiling is `u64::MAX`, so `>=`
///    never fires on it. This keeps the §5.4.5:558/563 **inclusive**
///    `chunks_billed` formula unchanged while guaranteeing the sealed
///    manifest never carries a billable `Data` at the cancel-ack slot (the
///    terminal is there), so the inclusive count correctly excludes it.
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
    // §5.4.5:530(3): the terminal cancel-ack chunk occupies `cancel_ack_seq`
    // (== the pinned next-to-emit cursor). Any non-terminal chunk the
    // executor emits at `sequence >= cancel_ack_seq` is a post-cancel
    // in-flight chunk that MUST be dropped-and-not-billed (§5.4.5:530(1)) —
    // dropping it here (a no-op that does not advance the emission cursor)
    // lets the terminal cancel-ack chunk land on `cancel_ack_seq`. For an
    // uncancelled stream `ceiling == u64::MAX`, so this never fires.
    if chunk.sequence >= ceiling {
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
/// Decrements the per-invoker and per-outlet counters on the per-context
/// `admission` tracker AND the per-origin-invoker counter on the
/// operator-scoped `origin_admission` tracker (§05-contexts.md:448),
/// under both trackers' critical sections. Idempotent on a
/// never-admitted triple (matches
/// [`super::stream::StreamAdmissionTracker::release`] semantics). The
/// caller MUST hold both write guards with the per-context lock acquired
/// before the operator-scoped one (the sanctioned lock order).
pub fn release_stream_admission(
    admission: &mut super::stream::StreamAdmissionTracker,
    origin_admission: &mut super::stream::OriginAdmissionTracker,
    invoker_did: &str,
    origin_invoker_did: &str,
    outlet_id: &str,
) {
    admission.release(origin_admission, invoker_did, origin_invoker_did, outlet_id);
}

// ---------------------------------------------------------------------------
// Panic guard (SCP-OUT-028 / ADR-049 §148)
// ---------------------------------------------------------------------------

/// Converts a recovered panic payload into a bounded UTF-8 message,
/// truncated to [`MESSAGE_MAX_BYTES`] (1 KiB) at a UTF-8 character
/// boundary.
#[allow(clippy::borrowed_box)] // downcasts the boxed panic payload directly.
fn panic_payload_to_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    let raw: &str = if let Some(s) = payload.downcast_ref::<&'static str>() {
        s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.as_str()
    } else {
        "<unknown panic payload>"
    };
    truncate_at_utf8_boundary(raw, MESSAGE_MAX_BYTES)
}

/// Truncates `s` to at most `max_bytes` bytes, splitting on a UTF-8
/// character boundary so the returned `String` is always valid UTF-8.
///
/// Used by [`panic_payload_to_message`] to bound panic messages by the
/// §5.4.4 `OutletError.message` cap. A naive `&s[..max_bytes]` would panic
/// when `max_bytes` lands inside a multi-byte UTF-8 codepoint; this helper
/// walks back to the previous codepoint boundary instead.
fn truncate_at_utf8_boundary(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    let mut cut = max_bytes;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s[..cut].to_owned()
}

/// Builds the `OutletVerifiedEvent { integrity_ok: false, reason:
/// HandlerPanicked }` signal for a recovered panic.
///
/// Mirrors the `QueryMisdeclaration` event construction — the parallel
/// §5.4.2 operator-attributable signal — with `reason: HandlerPanicked`
/// and `passed/failed = 0/1` so participation records (§7.3.2) attribute
/// exactly one integrity failure to the outlet's `operator_did`.
fn handler_panic_event(
    outlet_id: &OutletId,
) -> scp_protocol::context::outlets::OutletVerifiedEvent {
    scp_protocol::context::outlets::OutletVerifiedEvent {
        outlet_id: outlet_id.clone(),
        passed: 0,
        failed: 1,
        integrity_ok: false,
        reason: Some(scp_protocol::context::outlets::OutletVerifiedReason::HandlerPanicked),
    }
}

/// Runs an outlet executor (closure + future) under a
/// [`std::panic::catch_unwind`] guard so a panic inside `exec_query` /
/// `exec_action` is recovered into an [`InvocationError::HandlerPanic`]
/// envelope (SCP-OUT-028 / ADR-049 §148).
///
/// The guard wraps **both** the synchronous closure call (which constructs
/// the future) AND every poll of the resulting future. Panics during
/// future construction, during the executor's async body, during a
/// `.await` resume, or during the terminal value drop are all caught and
/// converted. Async runtimes (tokio) do not themselves panic-protect
/// spawned futures; without this guard a misbehaving operator handler
/// would unwind through `invoke_outlet` and abort the SCP runtime.
///
/// **Operator attribution.** Panics are NOT SDK-internal bugs: the SDK is
/// the entity that catches them. Per spec §5.4.2 the panic is recorded as
/// an operator-attributable
/// [`scp_protocol::context::outlets::OutletVerifiedEvent`] with
/// `reason: HandlerPanicked`, mirroring the `QueryMisdeclaration` parallel
/// signal. The runtime emits the event through `handler_panic_sink` when
/// one is wired; in either case it logs at `warn` level so operators see
/// the panic in their telemetry.
///
/// **Truncation.** The recovered panic payload is converted to a UTF-8
/// string via [`panic_payload_to_message`] and truncated to
/// [`MESSAGE_MAX_BYTES`] (1 KiB, matching the §5.4.4 `OutletError.message`
/// pre-HMAC cap).
async fn run_executor_with_panic_guard<F, Fut>(
    executor: F,
    input: serde_json::Value,
    outlet_id: &OutletId,
    handler_panic_sink: Option<&dyn HandlerPanicSink>,
) -> Result<Result<serde_json::Value, String>, InvocationError>
where
    F: FnOnce(serde_json::Value) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
{
    // Step A — synchronously construct the future, catching panics raised
    // BEFORE the first poll (e.g. closures that panic during pre-await
    // setup). `std::panic::catch_unwind` is sync-only, so the future
    // construction is captured here under the same payload-decoding rules
    // as the async path.
    let fut = match std::panic::catch_unwind(AssertUnwindSafe(|| executor(input))) {
        Ok(fut) => fut,
        Err(payload) => {
            return Err(panic_to_invocation_error(
                &payload,
                outlet_id,
                handler_panic_sink,
            ));
        }
    };

    // Step B — poll the future under `futures::FutureExt::catch_unwind`,
    // catching panics during any `.await` resume or during the body. The
    // `AssertUnwindSafe` is sound because the executor surface contract
    // (§5.4.2) treats the executor as a black box — the runtime does not
    // share mutable state with the executor across the panic boundary.
    match AssertUnwindSafe(fut).catch_unwind().await {
        Ok(executor_result) => Ok(executor_result),
        Err(payload) => Err(panic_to_invocation_error(
            &payload,
            outlet_id,
            handler_panic_sink,
        )),
    }
}

/// Converts a recovered panic payload into the typed
/// [`InvocationError::HandlerPanic`] envelope and emits the parallel
/// `OutletVerifiedEvent { reason: HandlerPanicked }` (§5.4.2) through
/// `handler_panic_sink` and a `warn`-level tracing event.
#[allow(clippy::borrowed_box)] // matches `panic_payload_to_message` which downcasts the boxed payload directly.
fn panic_to_invocation_error(
    payload: &Box<dyn std::any::Any + Send>,
    outlet_id: &OutletId,
    handler_panic_sink: Option<&dyn HandlerPanicSink>,
) -> InvocationError {
    let panic_message = panic_payload_to_message(payload);
    tracing::warn!(
        outlet_id = %outlet_id,
        code = CODE_EXECUTION_FAULT,
        slug = SLUG_EXECUTION_HANDLER_PANIC,
        panic_message = %panic_message,
        "outlet executor panicked — recovered via catch_unwind (operator-attributable, §5.4.2)"
    );
    if let Some(sink) = handler_panic_sink {
        sink.record(handler_panic_event(outlet_id));
    }
    InvocationError::HandlerPanic {
        outlet_id: outlet_id.clone(),
        panic_message,
    }
}

// ---------------------------------------------------------------------------
// invoke_outlet_dispatch — trait-executor routing (SCP-OUT-013 AC5)
// ---------------------------------------------------------------------------

/// Outcome of a successful [`invoke_outlet_dispatch`] call.
#[derive(Debug)]
pub struct DispatchedOutletOutcome {
    /// Outlet output (already schema-validated).
    pub output: serde_json::Value,
    /// Pending mutations from an Action outlet's [`MutableInvocation`]
    /// handle — empty for Query outlets (which can never enqueue
    /// mutations). The runtime's [`ContextManager`] is the canonical
    /// applier; direct callers may also drain them for testing or for
    /// custom mutation pipelines.
    ///
    /// [`ContextManager`]: crate::context::ContextManager
    pub pending_mutations: Vec<MutationIntent>,
    /// `OutletInvokedEvent` ready to be appended to the event log.
    pub event: OutletInvokedEvent,
    /// Triggered consequences from the post-invocation bookkeeping pass.
    pub consequences: Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
    /// Payment receipt when an adapter is configured for paid Action outlets.
    pub payment_receipt: Option<crate::economy::adapter::PaymentReceipt>,
}

/// Dispatches an outlet invocation through an [`OutletExecutor`], routing
/// to `exec_query` or `exec_action` based on the registered
/// [`OutletKind`].
///
/// PRD SCP-OUT-013 AC5: "`ContextManager::invoke_outlet` dispatches to
/// `exec_query` when `kind == Query` and `exec_action` when `kind ==
/// Action`." This free function is the underlying dispatcher; the
/// [`ContextManager::invoke_outlet_with_economy`](crate::context::ContextManager::invoke_outlet_with_economy)
/// wrapper layers the per-context economy/budget pipeline over the same
/// dispatch.
///
/// # Misdeclaration handling
///
/// When a Query-registered outlet's `exec_query` returns
/// [`OutletExecutorError::KindMismatch`] (the implementor failed to
/// override the Query half), the dispatcher records an
/// `OutletVerifiedEvent { integrity_ok: false, reason: QueryMisdeclaration }`
/// signal through `misdeclaration_sink` per spec §5.4.2. The
/// [`InvocationError::KindMismatch`] is then surfaced to the caller. The
/// Action-side mirror does NOT emit a `QueryMisdeclaration` signal because
/// the spec only attributes that signal to the Query path — Action
/// misdeclarations surface as `KindMismatch` without the operator-side
/// integrity-failure attribution.
///
/// # Errors
///
/// Returns the same [`InvocationError`] taxonomy as
/// [`invoke_outlet_aggregating`]. Misdeclarations surface as
/// [`InvocationError::KindMismatch`]; defense-in-depth runtime denies
/// surface as [`InvocationError::QueryViolation`]; other failures (schema,
/// timeout, capability) propagate verbatim from the underlying
/// closure-based pipeline.
///
/// [`OutletKind`]: scp_protocol::context::outlets::OutletKind
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // mirrors the aggregating `invoke_outlet` arity so the dispatcher is interchangeable; SCP-OUT-028 adds the panic sink at the end of the parameter list.
pub async fn invoke_outlet_dispatch<E, S>(
    context: &ContextHandle,
    registry: &OutletRegistry,
    role_state: &ContextRoleState,
    outlet_id: &OutletId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: &E,
    misdeclaration_sink: Option<&dyn QueryMisdeclarationSink>,
    economy: Option<&mut OutletEconomyContext<'_, S>>,
    handler_panic_sink: Option<&dyn HandlerPanicSink>,
) -> Result<DispatchedOutletOutcome, InvocationError>
where
    E: OutletExecutor + ?Sized,
    S: BuildHasher,
{
    // Snapshot the registered kind once so the closure-based delegate sees
    // a stable value even if the registry mutates between dispatch and
    // execution (the registry is not `&mut` here, so it cannot, but the
    // value is also borrowed by the executor closure below).
    let registration = registry
        .get(outlet_id)
        .ok_or_else(|| InvocationError::OutletNotFound {
            outlet_id: outlet_id.to_owned(),
        })?;
    let kind = registration.kind;

    // Snapshot the events the read handle exposes. The free
    // `invoke_outlet_aggregating` path does not have access to the
    // manager's event log here — the dispatcher takes an empty slice when
    // no economy context is supplied.
    // `ContextManager::invoke_outlet_dispatch_with_economy` wires the real
    // snapshot through.
    let empty_events: &[scp_event_log::Event] = &[];
    let events_snapshot: &[scp_event_log::Event] =
        economy.as_deref().map_or(empty_events, |econ| econ.events);

    // Build the read handle. Borrowing through the closure below carries
    // its lifetime; we extend the borrow scope to cover the executor
    // future.
    let outlet_id_cloned = outlet_id.clone();
    let invoker_did_cloned = invoker_did.clone();
    let read = ReadOnlyInvocation::new(
        context,
        role_state,
        registry,
        invoker_did,
        outlet_id,
        events_snapshot,
        // current_epoch is opaque at this layer; the
        // `invoke_outlet_with_economy_dispatch` wrapper threads the real MLS
        // epoch. Free callers see 0 — explicitly documented.
        0,
        economy.as_deref().and_then(|e| e.economic_policy),
        None,
    );

    // The closure-based `invoke_outlet_aggregating` path expects
    // `Fn(serde_json::Value) -> Future<Result<Value, String>>`. We adapt the
    // trait-based dispatch into that shape via a single-shot move closure.
    let mut pending_mutations: Vec<MutationIntent> = Vec::new();
    let pending_ref = &mut pending_mutations;
    let executor_ref: &E = executor;
    let read_ref = &read;
    let executor_kind = kind;
    let dispatch_outlet_id = outlet_id_cloned.clone();

    let dispatch = move |input: serde_json::Value| async move {
        match executor_kind {
            scp_protocol::context::outlets::OutletKind::Query => {
                match executor_ref.exec_query(read_ref, input).await {
                    Ok(value) => Ok(value),
                    Err(OutletExecutorError::KindMismatch { .. }) => {
                        // Spec §5.4.2 misdeclaration signal.
                        if let Some(sink) = misdeclaration_sink {
                            sink.record(
                                scp_protocol::context::outlets::OutletVerifiedEvent {
                                    outlet_id: dispatch_outlet_id.clone(),
                                    passed: 0,
                                    failed: 1,
                                    integrity_ok: false,
                                    reason: Some(
                                        scp_protocol::context::outlets::OutletVerifiedReason::QueryMisdeclaration,
                                    ),
                                },
                            );
                        }
                        Err(format!(
                            "{}",
                            OutletExecutorError::KindMismatch {
                                expected: scp_protocol::context::outlets::OutletKind::Query,
                            }
                        ))
                    }
                    Err(OutletExecutorError::QueryViolation { operation }) => {
                        // Should be impossible — `&ReadOnlyInvocation` has no
                        // write methods. Surface verbatim if it occurs.
                        Err(format!("query violation in exec_query: {operation}"))
                    }
                    Err(OutletExecutorError::Failed(msg)) => Err(msg),
                }
            }
            scp_protocol::context::outlets::OutletKind::Action => {
                let mut mutable = MutableInvocation::new(
                    ReadOnlyInvocation::new(
                        read_ref.context,
                        read_ref.role_state,
                        read_ref.registry,
                        read_ref.invoker_did,
                        read_ref.outlet_id,
                        read_ref.events,
                        read_ref.epoch,
                        read_ref.economic_policy,
                        read_ref.caveat_counters,
                    ),
                    scp_protocol::context::outlets::OutletKind::Action,
                    misdeclaration_sink,
                );
                let result = executor_ref.exec_action(&mut mutable, input).await;
                match result {
                    Ok(value) => {
                        pending_ref.extend(mutable.take_pending_mutations());
                        Ok(value)
                    }
                    Err(OutletExecutorError::KindMismatch { .. }) => Err(format!(
                        "{}",
                        OutletExecutorError::KindMismatch {
                            expected: scp_protocol::context::outlets::OutletKind::Action,
                        }
                    )),
                    Err(OutletExecutorError::QueryViolation { operation }) => {
                        Err(format!("query violation in exec_action: {operation}"))
                    }
                    Err(OutletExecutorError::Failed(msg)) => Err(msg),
                }
            }
        }
    };

    // Delegate to the closure-based pipeline so capability checks, schema
    // validation, escrow, budget, etc. all run as before. The closure
    // converts the trait error into the existing `String` error surface.
    // SCP-OUT-028: forward the handler-panic sink so panics inside
    // `exec_query` / `exec_action` emit the §5.4.2 attribution event.
    let result = invoke_outlet_aggregating(
        context,
        registry,
        role_state,
        outlet_id,
        input,
        invoker_did,
        timeout_ms,
        dispatch,
        economy,
        handler_panic_sink,
    )
    .await;

    let (output, event, consequences, payment_receipt) = match result {
        Ok(tuple) => tuple,
        Err(InvocationError::ExecutionFailed { message }) => {
            // Decode the structured error string back to the typed
            // KindMismatch / QueryViolation taxonomy.
            if message.starts_with("outlet executor kind mismatch") {
                return Err(InvocationError::KindMismatch {
                    outlet_id: outlet_id_cloned,
                    kind,
                });
            }
            if let Some(operation) = message.strip_prefix("query violation in exec_action: ") {
                return Err(InvocationError::QueryViolation {
                    outlet_id: outlet_id_cloned,
                    operation: query_violation_op_static(operation),
                });
            }
            if let Some(operation) = message.strip_prefix("query violation in exec_query: ") {
                return Err(InvocationError::QueryViolation {
                    outlet_id: outlet_id_cloned,
                    operation: query_violation_op_static(operation),
                });
            }
            return Err(InvocationError::ExecutionFailed { message });
        }
        Err(other) => return Err(other),
    };

    // Static suppression — the `_invoker_did_cloned` binding is only used
    // when the dispatch closure captures by move; under some compiler
    // configurations the `move` closure does not actually move it. Drop it
    // explicitly so the borrow checker keeps the lifetime sane and clippy
    // does not flag an unused variable.
    drop(invoker_did_cloned);

    Ok(DispatchedOutletOutcome {
        output,
        pending_mutations,
        event,
        consequences,
        payment_receipt,
    })
}

/// Coerces a runtime executor-supplied operation string back to one of the
/// `&'static str` constants used by the deny-list. The `MutableInvocation`
/// methods supply `&'static str` literals, so the round-trip preserves the
/// pointer when the original string was one of the known literals; for
/// unknown strings we fall back to a generic literal so the typed
/// [`InvocationError::QueryViolation`] still carries a `&'static str`.
fn query_violation_op_static(op: &str) -> &'static str {
    match op {
        "send_message" => "send_message",
        "assign_role" => "assign_role",
        "register_outlet" => "register_outlet",
        "append_event" => "append_event",
        "submit_governance_proposal" => "submit_governance_proposal",
        "cast_governance_vote" => "cast_governance_vote",
        "debit_economic_ledger" => "debit_economic_ledger",
        "credit_economic_ledger" => "credit_economic_ledger",
        "increment_caveat_counter" => "increment_caveat_counter",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// invoke_outlet — streaming entry point (SCP-OUT-033)
// ---------------------------------------------------------------------------

/// Default capacity of the chunk channel handed to the executor when the
/// invoker does not specify a `credit_window` (spec §5.4.5
/// `stream_window_default = 32`).
///
/// Mirrors [`scp_protocol::context::outlets::stream::DEFAULT_CREDIT_WINDOW`]
/// converted to a `usize` channel capacity. The conversion is bounded by
/// `usize::MAX` on every supported target.
#[allow(clippy::cast_possible_truncation)] // u32 → usize: 32 < usize::MAX on every target
const DEFAULT_STREAM_CHANNEL_CAPACITY: usize =
    scp_protocol::context::outlets::stream::DEFAULT_CREDIT_WINDOW as usize;

/// Generates a fresh `RequestId` (16-byte `UUIDv7`) for an outlet
/// invocation that did not receive one from a `OutletStreamOpen`
/// (i.e., a direct call into the streaming `invoke_outlet` entry
/// point).
///
/// Spec §5.4.5: `request_id: [u8; 16]` — per-stream `UUIDv7`,
/// monotonic time-sortable. Direct callers (tests, the manager
/// wrapper for non-stream-open paths) get a fresh `UUIDv7` so that
/// the chunk sequence space is unique to this invocation.
fn fresh_request_id() -> RequestId {
    *uuid::Uuid::now_v7().as_bytes()
}

/// Builds a terminal `ChunkPayload::Error` chunk with `terminal: true`
/// for an [`InvocationError`] that aborted the stream before/while the
/// executor was running (SCP-OUT-033 AC6, AC10, AC11).
///
/// Each `InvocationError` variant maps to one §5.4.4 sub-block code +
/// slug pair from [`scp_protocol::context::outlets::error_codes`].
#[must_use]
pub fn invocation_error_to_terminal_payload(err: &InvocationError) -> ChunkPayload {
    use scp_protocol::context::outlets::error_codes::{
        CODE_AUTHORIZATION_DENIED, CODE_ECONOMIC_FAULT, CODE_INPUT_VIOLATION,
        CODE_OUTPUT_VIOLATION, CODE_PROTOCOL_VIOLATION, SLUG_AUTHORIZATION_DENIED,
        SLUG_ECONOMIC_BUDGET_EXCEEDED, SLUG_INPUT_SCHEMA_VIOLATION, SLUG_OUTPUT_SCHEMA_VIOLATION,
        SLUG_QUERY_VIOLATION,
    };
    // The slug is included in the resulting Error chunk's `message`
    // field so the receiver-side SDK can reverse-lookup against the
    // §5.4.4 catalog. The `code` carries the §5.4.4 sub-block constant.
    let (code, slug) = match err {
        InvocationError::ContextNotActive { .. } => {
            (CODE_PROTOCOL_VIOLATION, "protocol.context-not-active")
        }
        // Spec §5.4.4 query-oracle-collapse: unknown outlets and
        // unauthorized callers both surface as `authorization.denied`
        // so the existence (or registration) of the outlet is not
        // leaked through the error class.
        InvocationError::InvokerNotAuthorized { .. } | InvocationError::OutletNotFound { .. } => {
            (CODE_AUTHORIZATION_DENIED, SLUG_AUTHORIZATION_DENIED)
        }
        InvocationError::InputValidationFailed { .. } => {
            (CODE_INPUT_VIOLATION, SLUG_INPUT_SCHEMA_VIOLATION)
        }
        InvocationError::OutputValidationFailed { .. } => {
            (CODE_OUTPUT_VIOLATION, SLUG_OUTPUT_SCHEMA_VIOLATION)
        }
        InvocationError::Timeout { .. } => (CODE_EXECUTION_FAULT, SLUG_EXECUTION_TIMEOUT),
        InvocationError::Cancelled => (CODE_EXECUTION_FAULT, "execution.cancelled"),
        InvocationError::ExecutionFailed { .. } | InvocationError::HandlerPanic { .. } => {
            (CODE_EXECUTION_FAULT, SLUG_EXECUTION_HANDLER_PANIC)
        }
        InvocationError::BudgetExceeded { .. } => (CODE_ECONOMIC_FAULT, "economic.budget-exceeded"),
        InvocationError::OutletQueryCostViolation { .. } => {
            (CODE_PROTOCOL_VIOLATION, "query-cost-violation")
        }
        InvocationError::QueryViolation { .. } => (CODE_PROTOCOL_VIOLATION, SLUG_QUERY_VIOLATION),
        InvocationError::KindMismatch { .. } => (CODE_PROTOCOL_VIOLATION, "kind-mismatch"),
        InvocationError::CaveatViolation {
            slug: caveat_slug, ..
        } => {
            // Caveat violations preserve the §5.4.4 slug from the rule
            // that fired; route the input-schema slug through the
            // input-class code, every other slug through the
            // authorization-denied class (matches
            // `invocation_error_to_context`'s slug→code routing).
            if caveat_slug.as_str() == SLUG_INPUT_SCHEMA_VIOLATION {
                (CODE_INPUT_VIOLATION, caveat_slug.as_str())
            } else {
                (CODE_AUTHORIZATION_DENIED, caveat_slug.as_str())
            }
        }
        // Exhaustiveness-only arm. `CrossContextPaidActionUnsupported` is an
        // OPEN-TIME economic rejection returned as `Err(InvocationError)`
        // before any stream/receiver exists (§5.4.5 "Cross-context economy"),
        // so it never legitimately reaches terminal-chunk conversion — the
        // cross-context bridge propagates it as a `Result::Err`, never as a
        // terminal chunk. It is an Economic-class rejection (`SCP-OUTLET-6150`)
        // — explicitly NOT a Transport fault (`SCP-OUTLET-6160`), which is the
        // mid-stream bridge-failure code. Because this arm is dead for terminal
        // conversion, it reuses the REGISTERED `SLUG_ECONOMIC_BUDGET_EXCEEDED`
        // slug (which round-trips `slug_to_class` to the Economic class) rather
        // than an unregistered bespoke literal — the real rejection detail is
        // carried by `{err}` in the message. Mapped here solely to keep the
        // match total.
        InvocationError::CrossContextPaidActionUnsupported { .. } => {
            (CODE_ECONOMIC_FAULT, SLUG_ECONOMIC_BUDGET_EXCEEDED)
        }
    };
    ChunkPayload::Error {
        code: code.to_owned(),
        message: format!("{slug}: {err}"),
        terminal: true,
    }
}

/// Maps an [`OutletExecutorError`] returned by `exec_*_stream` into the
/// terminal `ChunkPayload::Error { terminal: true, .. }` chunk the
/// framework appends to the stream (SCP-OUT-033 AC6).
fn executor_error_to_terminal_payload(err: &OutletExecutorError) -> ChunkPayload {
    use scp_protocol::context::outlets::error_codes::{
        CODE_PROTOCOL_VIOLATION, SLUG_KIND_MISMATCH, SLUG_QUERY_VIOLATION,
    };
    let (code, slug) = match err {
        OutletExecutorError::KindMismatch { .. } => (CODE_PROTOCOL_VIOLATION, SLUG_KIND_MISMATCH),
        OutletExecutorError::QueryViolation { .. } => {
            (CODE_PROTOCOL_VIOLATION, SLUG_QUERY_VIOLATION)
        }
        OutletExecutorError::Failed(_) => (CODE_EXECUTION_FAULT, SLUG_EXECUTION_HANDLER_PANIC),
    };
    ChunkPayload::Error {
        code: code.to_owned(),
        message: format!("{slug}: {err}"),
        terminal: true,
    }
}

/// Builds a placeholder `DataProvenance` used by the framework's
/// terminal `ChunkPayload::End` chunk when the streaming
/// `invoke_outlet` returns successfully (SCP-OUT-033 AC5).
///
/// Spec §5.4.5: `End { aggregate, provenance, execution_time_ms }`.
/// The free function `invoke_outlet` does not have access to the
/// hosting context's full provenance metadata — the manager wrapper
/// is responsible for richer attachment when crossing context
/// boundaries.
fn placeholder_data_provenance(context_id: &str) -> scp_protocol::provenance::DataProvenance {
    scp_protocol::provenance::DataProvenance {
        source_context: context_id.to_owned(),
        source_type: scp_protocol::provenance::SourceType::Persistent,
        counterparties: Vec::new(),
        purpose: None,
        discovery_method: scp_protocol::provenance::DiscoveryMethod::OutOfBand,
        age: std::time::Duration::from_secs(0),
        memory_scope: scp_protocol::context::params::MemoryScope::Full,
        chain_depth: 0,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    }
}

/// Wraps an inner `ChunkPayload` produced by the executor (or by the
/// framework's terminal-emission path) into a fully-formed
/// [`OutletStreamChunk`] with the next monotonic sequence number for
/// this `request_id` (SCP-OUT-033 AC4).
///
/// Signs the chunk under the §5.4.5 `SCP-OUTLET-CHUNK-SIG-V1:`
/// preimage with the supplied operator signing key when present. When
/// `signing_ctx.operator_signer` is `None`, emits the all-zero
/// placeholder and logs `tracing::error!` so the gap is visible —
/// production native paths always pass `Some`.
async fn wrap_chunk(
    signing_ctx: &InnerPumpSigningContext,
    request_id: RequestId,
    sequence: &mut u64,
    payload: ChunkPayload,
) -> OutletStreamChunk {
    let seq = *sequence;
    *sequence = sequence.saturating_add(1);
    let sig = signing_ctx
        .sign_inner_chunk(&request_id, seq, &payload)
        .await;
    OutletStreamChunk {
        request_id,
        sequence: seq,
        payload,
        sig,
    }
}

/// Identity-and-key bundle the inner pump uses to sign every chunk
/// under the §5.4.5 `SCP-OUTLET-CHUNK-SIG-V1:` preimage.
///
/// Mirror of `dispatch::PumpSigningContext` — kept distinct to
/// preserve the layer boundary between the inner executor pump
/// (`invoke.rs`, no admission/credit gate) and the outer dispatch
/// pump (`dispatch.rs`, owns admission + credit + cancel-ack).
#[derive(Clone)]
pub(crate) struct InnerPumpSigningContext {
    /// Operator streaming signer. `None` for legacy / test callers that
    /// did not wire a signer — `wrap_chunk` falls back to the all-zero
    /// placeholder + a `tracing::error!` log so the gap is visible.
    pub(crate) operator_signer: Option<std::sync::Arc<dyn super::signer::StreamSigner>>,
    /// Hosting context id (committed into the preimage).
    pub(crate) context_id: String,
    /// Outlet id (committed into the preimage).
    pub(crate) outlet_id: String,
    /// 32-byte `caveats_binding` (committed into the preimage).
    pub(crate) caveats_binding: [u8; 32],
}

impl InnerPumpSigningContext {
    /// Signs a `(request_id, sequence, payload)` triple under the
    /// pinned `(context_id, outlet_id, caveats_binding)`. Returns the
    /// 64-byte signature, or the all-zero placeholder + a
    /// `tracing::error!` log when the signer is `None` / when JCS or the
    /// signer fails.
    async fn sign_inner_chunk(
        &self,
        request_id: &RequestId,
        sequence: u64,
        payload: &ChunkPayload,
    ) -> [u8; 64] {
        let Some(signer) = self.operator_signer.as_ref() else {
            tracing::error!(
                request_id = %hex::encode(request_id),
                outlet_id = %self.outlet_id,
                context_id = %self.context_id,
                sequence,
                "invoke pump: operator_signer is None — emitting unsigned chunk (legacy/test path)"
            );
            return [0u8; 64];
        };
        let preimage = match scp_protocol::context::outlets::stream::compute_chunk_sig_preimage(
            &self.context_id,
            &self.outlet_id,
            request_id,
            sequence,
            &self.caveats_binding,
            payload,
        ) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(
                    request_id = %hex::encode(request_id),
                    outlet_id = %self.outlet_id,
                    context_id = %self.context_id,
                    sequence,
                    error = %e,
                    "invoke pump: failed to compute chunk preimage — emitting unsigned placeholder"
                );
                return [0u8; 64];
            }
        };
        match signer.sign(&preimage).await {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!(
                    request_id = %hex::encode(request_id),
                    outlet_id = %self.outlet_id,
                    context_id = %self.context_id,
                    sequence,
                    error = %e,
                    "invoke pump: signer failed to sign chunk — emitting unsigned placeholder"
                );
                [0u8; 64]
            }
        }
    }
}

/// SCP-OUT-021 — caveat post-input check hook (§7.3.8).
///
/// The §7.3.8 caveat-enforcement seam: a boxed one-shot closure that owns
/// the synchronous local checks
/// ([`InvocationCaveats::check_invocation_local`](scp_protocol::trust::caveats::InvocationCaveats::check_invocation_local))
/// AND the asynchronous counter-store calls
/// (`max_calls`, `amount_max_cumulative`, `rate_window`) — combining both
/// into one closure preserves the §7.3.8 ordering invariant: synchronous
/// caveats first (so a fast rejection does not consume counter capacity),
/// counter-store next (atomic per-UCAN CAS).
///
/// A stream validates its input ONCE at open (§5.4.5), so the streaming
/// dispatch open path
/// ([`open_stream_session`](crate::context::outlets::dispatch::open_stream_session))
/// runs this hook at that single open-time validation point, immediately
/// after input-schema validation and before the pump spawns. The type is
/// defined here in `invoke` because it is the shared §7.3.8 caveat seam
/// built identically for the streaming and non-streaming paths.
///
/// On failure the hook returns [`InvocationError`] (typically
/// [`InvocationError::InputValidationFailed`] or a manager-mapped
/// authorization error); on success it returns `Ok(())` and the caller
/// proceeds.
///
/// The hook receives a borrowed reference to the input `serde_json::Value`
/// so the same value the executor will see (and the input hash will be
/// computed from) is what the schema check observes. The hook MUST NOT
/// mutate the input.
pub type CaveatPostInputCheck<'a> = Box<
    dyn FnOnce(
            &serde_json::Value,
        )
            -> std::pin::Pin<Box<dyn Future<Output = Result<(), InvocationError>> + Send + 'a>>
        + Send
        + 'a,
>;

/// Streaming entry point for outlet invocation (SCP-OUT-033).
///
/// Returns a `mpsc::Receiver<OutletStreamChunk>` that yields the chunks
/// produced by the executor (`Data` / `Progress`), terminated by a
/// single terminal chunk (`End` on success, `Error { terminal: true }`
/// on failure). The framework spawns a tokio task that drives the
/// executor and pumps chunks into the channel.
///
/// This is the streaming counterpart of the unary
/// [`invoke_outlet_aggregating`] (best-effort *outlet stream* mode per
/// ADR-061). The two modes are distinct: unary commits `output_hash`,
/// streaming commits `stream_manifest_hash`.
///
/// # Sequence numbering
///
/// `sequence` starts at `0` and is strictly monotonic per `request_id`
/// (§5.4.5). The framework assigns sequence numbers — the executor
/// only writes `ChunkPayload` values, never `OutletStreamChunk`. The
/// terminal chunk shares the same `request_id` and is at the next
/// sequence after the last `Data` chunk.
///
/// # Timeout enforcement
///
/// `timeout_ms` enforces a hard deadline. On timeout the framework emits
/// a terminal `ChunkPayload::Error` chunk and drops the executor task.
///
/// # Panic guard
///
/// The executor task runs inside `catch_unwind`. Panics inside the
/// executor are recovered into a terminal `ChunkPayload::Error` chunk
/// per SCP-OUT-028 / ADR-049 §148.
///
/// # Errors
///
/// Returns [`InvocationError`] only for the **synchronous** validation
/// failures that happen BEFORE the stream is opened (context state,
/// capability, registry lookup, input schema). Once the receiver is
/// returned, every failure mode (timeout, panic, executor `Err`,
/// caveat violation, output schema) surfaces as a terminal
/// `ChunkPayload::Error` chunk on the receiver — never as a `Result`
/// error.
#[allow(clippy::too_many_arguments)]
// mirrors invoke_outlet_aggregating's parameter set so the streaming/aggregating split is interchangeable for callers that hold the same surrounding state.
#[allow(clippy::unused_async)] // public streaming entry point: async for API parity with invoke_outlet_aggregating and the manager wrapper; the body only awaits on this branch when `context.state()` is async (it is sync here, so no await is emitted).
pub async fn invoke_outlet<E>(
    context: &ContextHandle,
    registry: &OutletRegistry,
    role_state: &ContextRoleState,
    outlet_id: &OutletId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: std::sync::Arc<E>,
    misdeclaration_sink: Option<std::sync::Arc<dyn QueryMisdeclarationSink>>,
    handler_panic_sink: Option<std::sync::Arc<dyn HandlerPanicSink>>,
    invoked_event_sink: Option<std::sync::Arc<dyn OutletInvokedEventSink>>,
    // Operator streaming signer used to sign every chunk under §5.4.5
    // `SCP-OUTLET-CHUNK-SIG-V1:`. `None` is reserved for legacy / test
    // callers; production native paths always supply `Some`. A
    // `StreamSigner` trait object so the inner pump signs through the same
    // custody-injectable seam as the dispatch pump. See
    // `InnerPumpSigningContext` for the fallback behaviour.
    operator_signer: Option<std::sync::Arc<dyn super::signer::StreamSigner>>,
    // 32-byte `caveats_binding` pinned at acceptance — committed into
    // the per-chunk-signature preimage. `[0u8; 32]` for legacy / test
    // callers; production paths supply the real binding.
    caveats_binding: [u8; 32],
) -> Result<mpsc::Receiver<OutletStreamChunk>, InvocationError>
where
    E: OutletExecutor + ?Sized + 'static,
{
    // Step 1-4 (synchronous): validate context state, registry, capability,
    // input schema BEFORE opening the stream. A `Result::Err` here means
    // the open was rejected before the stream was created — the receiver
    // has not been allocated yet.
    let state = context.state();
    if state != ContextState::Active {
        return Err(InvocationError::ContextNotActive {
            current_state: state.to_string(),
        });
    }
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
    // SCP-OUT-035: snapshot the input hash before handing the value to
    // the executor so the §5.4.5 event records what the executor saw
    // even if the executor mutates the value internally.
    let input_hash = sha256_json(&input);

    // Open the stream. The channel capacity matches the §5.4.5
    // `credit_window` default (32). When the buffer fills, the executor
    // back-pressures until a downstream consumer drains a slot.
    let (chunk_tx, chunk_rx) = mpsc::channel::<OutletStreamChunk>(DEFAULT_STREAM_CHANNEL_CAPACITY);
    let (payload_tx, payload_rx) = mpsc::channel::<ChunkPayload>(DEFAULT_STREAM_CHANNEL_CAPACITY);

    let request_id = fresh_request_id();
    let outlet_id_owned: OutletId = outlet_id.clone();
    let invoker_did_owned: DID = invoker_did.clone();
    let context_id_owned: String = context.context_id().to_owned();
    let context_handle_owned = context.clone();
    let role_state_owned = role_state.clone();
    let registry_owned = registry.clone();
    let kind = registration.kind;
    // Per-Data output-schema validation is intentionally NOT performed
    // by the streaming entry point — the aggregating path validates the
    // post-executor `Value` against `output_schema`, and a streaming
    // executor's per-chunk values are validated by the SDK / consumer
    // instead.
    let _ = registration.schema.output_schema;
    let effective_timeout = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS).min(MAX_TIMEOUT_MS);
    let timeout_duration = Duration::from_millis(u64::from(effective_timeout));

    let signing_ctx = InnerPumpSigningContext {
        operator_signer,
        context_id: context_id_owned.clone(),
        outlet_id: outlet_id_owned.clone(),
        caveats_binding,
    };
    let task_inputs = StreamingTaskInputs {
        context: context_handle_owned,
        role_state: role_state_owned,
        registry: registry_owned,
        invoker_did: invoker_did_owned,
        outlet_id: outlet_id_owned,
        context_id: context_id_owned,
        request_id,
        kind,
        input,
        input_hash,
        executor: std::sync::Arc::clone(&executor),
        misdeclaration_sink,
        handler_panic_sink,
        invoked_event_sink,
        chunk_tx,
        payload_tx,
        payload_rx,
        timeout_duration,
        effective_timeout,
        signing_ctx,
    };
    tokio::spawn(run_streaming_executor_task(task_inputs));

    Ok(chunk_rx)
}

/// Bundle of inputs handed to the spawned streaming task body.
///
/// Splitting these out keeps [`invoke_outlet`] under the workspace's
/// `clippy::too_many_lines` ceiling: the synchronous-validation half
/// stays in the public function and the spawned-task driver lives in
/// [`run_streaming_executor_task`].
struct StreamingTaskInputs<E: ?Sized> {
    context: ContextHandle,
    role_state: ContextRoleState,
    registry: OutletRegistry,
    invoker_did: DID,
    outlet_id: OutletId,
    context_id: String,
    request_id: RequestId,
    kind: scp_protocol::context::outlets::OutletKind,
    input: serde_json::Value,
    /// Pre-computed input hash (SHA-256 over canonical JSON of the
    /// invocation input). Captured at stream open so the §5.4.5
    /// `OutletInvokedEvent.input_hash` is available even when the
    /// executor mutates the input value internally before producing
    /// chunks.
    input_hash: String,
    executor: std::sync::Arc<E>,
    misdeclaration_sink: Option<std::sync::Arc<dyn QueryMisdeclarationSink>>,
    handler_panic_sink: Option<std::sync::Arc<dyn HandlerPanicSink>>,
    /// SCP-OUT-035 §5.4.5 event-log sink: receives exactly one
    /// `OutletInvokedEvent` at stream close. `None` disables emission
    /// entirely (legacy callers who don't append events to the log).
    invoked_event_sink: Option<std::sync::Arc<dyn OutletInvokedEventSink>>,
    chunk_tx: mpsc::Sender<OutletStreamChunk>,
    payload_tx: mpsc::Sender<ChunkPayload>,
    payload_rx: mpsc::Receiver<ChunkPayload>,
    timeout_duration: Duration,
    effective_timeout: u32,
    /// Operator signing context for per-chunk signing under
    /// `SCP-OUTLET-CHUNK-SIG-V1:`. When the dispatch pump wraps this
    /// task it will re-sign every chunk under the renumbered outer
    /// sequence; the inner sig closes the spec-compliance loop for
    /// callers that bypass the dispatch pump (manager-direct or test
    /// callers).
    signing_ctx: InnerPumpSigningContext,
}

/// Drives the streaming executor under panic guard + timeout, pumps
/// payloads to chunks with monotonic sequence, and emits the terminal
/// `End`/`Error` chunk (SCP-OUT-033).
///
/// Extracted from [`invoke_outlet`] so the public function stays under
/// the `clippy::too_many_lines` ceiling. The task runs on the tokio
/// runtime; when it finishes, the chunk channel closes and the
/// receiver returned to the caller observes EOS.
#[allow(
    clippy::too_many_lines,
    reason = "single linear drive→pump→terminal→emit sequence; splitting further would thread the frontier/terminal-summary/signing-ctx state across seams for no clarity gain"
)]
async fn run_streaming_executor_task<E>(inputs: StreamingTaskInputs<E>)
where
    E: OutletExecutor + ?Sized + 'static,
{
    let StreamingTaskInputs {
        context,
        role_state,
        registry,
        invoker_did,
        outlet_id,
        context_id,
        request_id,
        kind,
        input,
        input_hash,
        executor,
        misdeclaration_sink,
        handler_panic_sink,
        invoked_event_sink,
        chunk_tx,
        payload_tx,
        mut payload_rx,
        timeout_duration,
        effective_timeout,
        signing_ctx,
    } = inputs;

    let start = std::time::Instant::now();
    let mut sequence: u64 = 0;
    let outlet_id_for_emit = outlet_id.clone();
    let invoker_did_for_event = invoker_did.clone();
    // SCP-OUT-035 / ADR-061: fold every emitted chunk into the O(log n)
    // RFC-6962 Merkle frontier (running manifest root + counts) and the
    // O(1) terminal summary — never retain the full payload set (ADR-061:
    // the pump "never accumulates the full payload set in memory"). The
    // inner capture pump has no cancel/credit gate, so the frontier's
    // billing ceiling is unbounded (`MerkleFrontier::new`): every `Data`
    // chunk is billable, matching the pre-refactor batch count.
    let mut frontier = scp_protocol::context::outlets::stream::MerkleFrontier::new();
    let mut terminal_summary = StreamTerminalSummary::default();

    // Build the executor future under `catch_unwind` so panics inside
    // the executor body recover into a terminal `Error` chunk
    // (SCP-OUT-028 streaming variant). See `build_executor_future`.
    let executor_future = build_executor_future(ExecutorFutureInputs {
        context,
        role_state,
        registry,
        invoker_did,
        outlet_id,
        kind,
        input,
        executor,
        misdeclaration_sink,
        payload_tx: payload_tx.clone(),
    });

    // Drop the original `payload_tx` retained by this scope so the
    // payload pump observes EOS as soon as the executor's clone is
    // dropped.
    drop(payload_tx);

    tokio::pin!(executor_future);

    let pump_outcome = pump_payload_stream_capture(
        &mut payload_rx,
        &chunk_tx,
        &mut sequence,
        request_id,
        executor_future,
        timeout_duration,
        &mut frontier,
        &mut terminal_summary,
        &signing_ctx,
    )
    .await;

    if !pump_outcome.chunk_tx_alive {
        // Receiver dropped mid-stream; no terminal chunk is emitted.
        // The §5.4.5 event-log shape says one event per stream, but
        // the contract is "after terminal chunk is delivered to the
        // receiver" — when the receiver disconnects there is no
        // delivery. Skip emission to keep the audit log honest.
        return;
    }

    // After exiting the pump, drain any payloads the executor already
    // pushed but the pump did not yet observe. Guards against the race
    // where the executor finished simultaneously with the deadline.
    if !pump_outcome.timed_out {
        while let Ok(payload) = payload_rx.try_recv() {
            let chunk = wrap_chunk(&signing_ctx, request_id, &mut sequence, payload).await;
            ingest_stream_chunk(&mut frontier, &mut terminal_summary, &chunk);
            if chunk_tx.send(chunk).await.is_err() {
                // Receiver dropped during late drain; same rationale
                // as above — skip the event-log emission.
                return;
            }
        }
    }

    // Emit the terminal chunk based on the executor outcome / timeout
    // / panic.
    let terminal_payload = build_terminal_chunk(BuildTerminalChunkInputs {
        timed_out: pump_outcome.timed_out,
        executor_outcome: pump_outcome.executor_outcome,
        outlet_id: &outlet_id_for_emit,
        context_id: &context_id,
        effective_timeout,
        start,
        handler_panic_sink: handler_panic_sink.as_deref(),
    });

    let terminal_chunk =
        wrap_chunk(&signing_ctx, request_id, &mut sequence, terminal_payload).await;
    ingest_stream_chunk(&mut frontier, &mut terminal_summary, &terminal_chunk);
    let delivered = chunk_tx.send(terminal_chunk).await.is_ok();

    if !delivered {
        // Receiver dropped before the terminal chunk landed — same
        // rationale as the early-exit branch above.
        return;
    }

    // SCP-OUT-035 §5.4.5: emit ONE OutletInvokedEvent at stream close,
    // AFTER the terminal chunk has been delivered to the receiver.
    if let Some(sink) = invoked_event_sink {
        let event = build_streaming_outlet_event(
            request_id,
            &outlet_id_for_emit,
            &invoker_did_for_event,
            input_hash,
            elapsed_ms(start),
            u32::try_from(frontier.leaf_count()).unwrap_or(u32::MAX),
            u32::try_from(frontier.billed_count()).unwrap_or(u32::MAX),
            frontier.root(),
            &terminal_summary,
            // Inner invoke pump has no separate running tally to diverge
            // from — the frontier IS the tally — so no anomaly is possible
            // here.
            None,
            // Inner invoke pump does not process `OutletCancel` — it has no
            // cancel-ack ceiling, so the billing ceiling is `u64::MAX`.
            None,
        );
        sink.record(event);
    }
}

/// Builds the §5.4.5 `OutletInvokedEvent` from a complete recorded
/// chunk sequence (SCP-OUT-035).
///
/// `request_id` is the per-stream `[u8; 16]` UUID. The `OutletInvokedEvent`
/// stores the request id as a hex-encoded string for cross-bridge
/// stability — the bytes themselves remain the canonical form on the
/// stream wire types.
/// Terminal-derived fields of an [`OutletInvokedEvent`] — the pieces the
/// batch builder used to recompute by scanning the whole chunk slice
/// (`output_hash`, `stream_terminal_status`, legacy `status`).
///
/// Only `End` and terminal `Error` chunks mutate the summary, and both
/// are terminal (the last chunk a stream emits), so folding one chunk at
/// a time via [`Self::observe`] yields the identical result as a batch
/// scan of the full sequence — while retaining `O(1)` state instead of
/// the chunk Vec (ADR-061: the pump "never accumulates the full payload
/// set in memory"). The Merkle root, `stream_chunk_count`, and
/// `chunks_billed` come from the sibling
/// [`scp_protocol::context::outlets::stream::MerkleFrontier`].
#[derive(Debug, Clone)]
pub struct StreamTerminalSummary {
    output_hash: Option<String>,
    terminal_status: StreamTerminalStatus,
    legacy_status: OutletStatus,
}

impl Default for StreamTerminalSummary {
    /// A stream that ends WITHOUT an `End` or terminal `Error` chunk (the
    /// receiver dropped, signing failed, upstream closed) records the
    /// §5.4.5 default `Error(CODE_EXECUTION_FAULT)` terminal — the same
    /// value the batch builder started its scan from.
    fn default() -> Self {
        Self {
            output_hash: None,
            terminal_status: StreamTerminalStatus::Error(CODE_EXECUTION_FAULT.to_owned()),
            legacy_status: OutletStatus::Error,
        }
    }
}

impl StreamTerminalSummary {
    /// Folds one emitted chunk's payload into the terminal summary. `Data`
    /// and `Progress` (and non-terminal `Error`) leave it unchanged; `End`
    /// sets `Ok` + `output_hash`; a terminal `Error` sets `Error(code)`.
    /// Chunks MUST be observed in emission order (last write wins, exactly
    /// as the batch scan resolved it).
    pub fn observe(&mut self, payload: &ChunkPayload) {
        match payload {
            ChunkPayload::Data { .. } | ChunkPayload::Progress { .. } => {}
            ChunkPayload::End { aggregate, .. } => {
                self.terminal_status = StreamTerminalStatus::Ok;
                self.legacy_status = OutletStatus::Success;
                self.output_hash = Some(scp_protocol::context::outlets::lifecycle::sha256_json(
                    aggregate,
                ));
            }
            ChunkPayload::Error { code, terminal, .. } => {
                if *terminal {
                    self.terminal_status = StreamTerminalStatus::Error(code.clone());
                    self.legacy_status = OutletStatus::Error;
                }
            }
        }
    }
}

/// Folds one emitted chunk into the streaming aggregates: its leaf hash
/// into the RFC-6962 [`MerkleFrontier`](scp_protocol::context::outlets::stream::MerkleFrontier)
/// (running manifest root + counts) and its payload into the
/// [`StreamTerminalSummary`]. Shared by the inner capture pump and the
/// outer dispatch pump so both fold identically.
///
/// A JCS leaf-hash failure is unreachable for an operator-signed chunk
/// (signing canonicalizes the same payload before this call), but is
/// logged rather than swallowed so a genuine encoding fault surfaces
/// instead of silently dropping a chunk from the manifest.
pub(crate) fn ingest_stream_chunk(
    frontier: &mut scp_protocol::context::outlets::stream::MerkleFrontier,
    terminal: &mut StreamTerminalSummary,
    chunk: &OutletStreamChunk,
) {
    if let Err(err) = frontier.push(chunk) {
        tracing::error!(
            sequence = chunk.sequence,
            %err,
            "outlet stream chunk failed JCS leaf-hash during Merkle-frontier ingest — \
             manifest root will not cover this chunk"
        );
    }
    terminal.observe(&chunk.payload);
}

/// Assembles the §5.4.5 `OutletInvokedEvent` from the precomputed stream
/// aggregates (SCP-OUT-035). The `stream_manifest_hash`,
/// `stream_chunk_count`, and `chunks_billed` are produced incrementally
/// by the [`MerkleFrontier`](scp_protocol::context::outlets::stream::MerkleFrontier)
/// as chunks are emitted; the terminal-derived fields come from
/// [`StreamTerminalSummary`]. This is the seam ADR-061 requires: the pump
/// builds the event from an `O(log n)` frontier + `O(1)` terminal summary,
/// never a retained chunk Vec.
#[allow(clippy::too_many_arguments)] // Assembles one flat event record from independent scalar aggregates (ids, hashes, counts, terminal summary); a wrapper struct would just relocate the same fields.
pub(crate) fn build_streaming_outlet_event(
    request_id: RequestId,
    outlet_id: &OutletId,
    invoker_did: &DID,
    input_hash: String,
    execution_time_ms: u64,
    stream_chunk_count: u32,
    chunks_billed: u32,
    stream_manifest_hash: [u8; 32],
    terminal: &StreamTerminalSummary,
    // §5.4.5 round-8 (F2): set when the dispatch pump detected a divergence
    // between its own running `chunks_billed` tally and the frontier-derived
    // reference. The event carries the frontier-derived value regardless;
    // this marker records the divergence so it is durably attributable in
    // the audit log instead of dropping the event. `None` on the happy path
    // and for the inner-invoke pump (which does not maintain a separate
    // running tally to diverge from).
    audit_anomaly: Option<scp_protocol::context::outlets::lifecycle::AuditAnomaly>,
    // §5.4.5:558-566 cancel-ack billing ceiling. `Some(seq)` records the
    // pinned cancel-ack sequence written into the event alongside
    // `stream_terminal_status` (the highest `Data`-chunk sequence still
    // billable). `None` when the stream terminated without a cancel-ack, in
    // which case the §5.4.5 predicate ceiling is `u64::MAX`.
    cancel_ack_seq: Option<u64>,
) -> OutletInvokedEvent {
    // §5.4.5:578 — a stream closed by a *graceful* cancel-ack (an
    // `OutletCancel` was observed AND the executor delivered a normal `End`
    // within the cancel-ack window) records the dedicated `Cancelled`
    // terminal status rather than `Ok`, so the audit record distinguishes a
    // cancellation from an uncancelled completion. A cancel that instead
    // closes via a terminal `Error` (an executor error, or the
    // `SCP-OUTLET-6135` cancel-ack-timeout) keeps `Error(code)` — the failure
    // is the more informative status and AC13 expects `6135` there.
    // `cancel_ack_seq.is_some()` witnesses "a cancel was observed"; the
    // inner-invoke pump passes `None` and therefore never reports `Cancelled`.
    let (legacy_status, terminal_status) = match (cancel_ack_seq, &terminal.terminal_status) {
        (Some(_), StreamTerminalStatus::Ok) => {
            (OutletStatus::Cancelled, StreamTerminalStatus::Cancelled)
        }
        _ => (terminal.legacy_status, terminal.terminal_status.clone()),
    };
    OutletInvokedEvent {
        request_id: hex::encode(request_id),
        outlet_id: outlet_id.to_owned(),
        invoker_did: invoker_did.clone(),
        status: legacy_status,
        execution_time_ms,
        input_hash,
        output_hash: terminal.output_hash.clone(),
        // §5.4.5:570-579 defines the streaming `OutletInvokedEvent` shape
        // with exactly the four stream fields below and NO `cost`. Per
        // §5.4.5:555 + §19.15.5 the per-stream billed amount is recorded in
        // the close-time `PaymentReceipt` (issued by the settlement sink),
        // not duplicated on this event. Recording it here would put an
        // economic value on a field the spec's event shape omits and
        // duplicate the receipt's authoritative amount — a divergence, not a
        // completeness fix. `cost` therefore stays `None` on the streaming
        // path (the settlement sink at stream close owns the amount).
        cost: None,
        stream_chunk_count,
        chunks_billed,
        stream_manifest_hash,
        stream_terminal_status: terminal_status,
        cancel_ack_seq,
        audit_anomaly,
    }
}

/// Variant of a payload pump that folds every chunk emitted by the
/// executor into the RFC-6962 Merkle `frontier` + `terminal` summary
/// (SCP-OUT-035 / ADR-061) so the runtime can compute the §5.4.5
/// chunk-manifest Merkle root at stream close WITHOUT retaining the
/// payload set.
#[allow(clippy::too_many_arguments)] // signing_ctx is the wire-signing addition; bundling it would require a wrapper struct that obscures the small parameter set.
async fn pump_payload_stream_capture<F>(
    payload_rx: &mut mpsc::Receiver<ChunkPayload>,
    chunk_tx: &mpsc::Sender<OutletStreamChunk>,
    sequence: &mut u64,
    request_id: RequestId,
    executor_future: std::pin::Pin<&mut F>,
    timeout_duration: Duration,
    frontier: &mut scp_protocol::context::outlets::stream::MerkleFrontier,
    terminal: &mut StreamTerminalSummary,
    signing_ctx: &InnerPumpSigningContext,
) -> PumpOutcome
where
    F: Future<Output = Result<Result<(), OutletExecutorError>, Box<dyn std::any::Any + Send>>>
        + Send,
{
    let mut executor_future = executor_future;
    let mut deadline = std::pin::pin!(tokio::time::sleep(timeout_duration));
    let mut executor_outcome: Option<
        Result<Result<(), OutletExecutorError>, Box<dyn std::any::Any + Send>>,
    > = None;
    let mut timed_out = false;
    let mut chunk_tx_alive = true;

    loop {
        tokio::select! {
            biased;

            outcome = &mut executor_future, if executor_outcome.is_none() => {
                executor_outcome = Some(outcome);
            }

            next_payload = payload_rx.recv() => {
                match next_payload {
                    Some(payload) => {
                        let chunk =
                            wrap_chunk(signing_ctx, request_id, sequence, payload).await;
                        ingest_stream_chunk(frontier, terminal, &chunk);
                        if chunk_tx.send(chunk).await.is_err() {
                            chunk_tx_alive = false;
                            break;
                        }
                    }
                    None => {
                        if executor_outcome.is_some() {
                            break;
                        }
                    }
                }
            }

            () = &mut deadline, if !timed_out => {
                timed_out = true;
                break;
            }
        }
    }

    PumpOutcome {
        timed_out,
        chunk_tx_alive,
        executor_outcome,
    }
}

/// Inputs for [`build_executor_future`] — the helper that constructs
/// the panic-guarded executor future for the streaming pipeline.
struct ExecutorFutureInputs<E: ?Sized> {
    context: ContextHandle,
    role_state: ContextRoleState,
    registry: OutletRegistry,
    invoker_did: DID,
    outlet_id: OutletId,
    kind: scp_protocol::context::outlets::OutletKind,
    input: serde_json::Value,
    executor: std::sync::Arc<E>,
    misdeclaration_sink: Option<std::sync::Arc<dyn QueryMisdeclarationSink>>,
    payload_tx: mpsc::Sender<ChunkPayload>,
}

/// Builds the panic-guarded executor future the streaming pipeline
/// races against the deadline. The returned future is
/// `AssertUnwindSafe(...).catch_unwind()`-wrapped so the pump can
/// distinguish executor-`Err`, executor-success, and recovered panics
/// (SCP-OUT-028 streaming variant of ADR-049 §148).
fn build_executor_future<E>(
    inputs: ExecutorFutureInputs<E>,
) -> futures::future::CatchUnwind<
    AssertUnwindSafe<impl Future<Output = Result<(), OutletExecutorError>> + Send>,
>
where
    E: OutletExecutor + ?Sized + 'static,
{
    let ExecutorFutureInputs {
        context,
        role_state,
        registry,
        invoker_did,
        outlet_id,
        kind,
        input,
        executor,
        misdeclaration_sink,
        payload_tx,
    } = inputs;
    AssertUnwindSafe(async move {
        let read = ReadOnlyInvocation::new(
            &context,
            &role_state,
            &registry,
            &invoker_did,
            &outlet_id,
            &[],
            0,
            None,
            None,
        );
        match kind {
            scp_protocol::context::outlets::OutletKind::Query => {
                executor.exec_query_stream(&read, input, payload_tx).await
            }
            scp_protocol::context::outlets::OutletKind::Action => {
                let mut mutable = MutableInvocation::new(
                    ReadOnlyInvocation::new(
                        &context,
                        &role_state,
                        &registry,
                        &invoker_did,
                        &outlet_id,
                        &[],
                        0,
                        None,
                        None,
                    ),
                    scp_protocol::context::outlets::OutletKind::Action,
                    misdeclaration_sink
                        .as_deref()
                        .map(|sink| sink as &dyn QueryMisdeclarationSink),
                );
                executor
                    .exec_action_stream(&mut mutable, input, payload_tx)
                    .await
            }
        }
    })
    .catch_unwind()
}

/// Outcome of [`pump_payload_stream_capture`] handed back to
/// [`run_streaming_executor_task`].
struct PumpOutcome {
    /// Whether the deadline fired (timeout) before the executor
    /// finished.
    timed_out: bool,
    /// Whether the chunk-sender was still alive when the pump exited
    /// (consumer didn't drop the receiver mid-stream).
    chunk_tx_alive: bool,
    /// `None` when timed out; `Some(Ok(Ok(())))` for a normal Ok
    /// completion, `Some(Ok(Err(...)))` for executor-internal failure,
    /// `Some(Err(payload))` for a recovered panic.
    executor_outcome:
        Option<Result<Result<(), OutletExecutorError>, Box<dyn std::any::Any + Send>>>,
}

/// Inputs for [`build_terminal_chunk`] — the framework's terminal
/// `End` / `Error` chunk emission helper.
struct BuildTerminalChunkInputs<'a> {
    timed_out: bool,
    executor_outcome:
        Option<Result<Result<(), OutletExecutorError>, Box<dyn std::any::Any + Send>>>,
    outlet_id: &'a OutletId,
    context_id: &'a str,
    effective_timeout: u32,
    start: std::time::Instant,
    handler_panic_sink: Option<&'a dyn HandlerPanicSink>,
}

/// Builds the §5.4.5 terminal chunk for a streaming outlet invocation
/// (SCP-OUT-033). One of: `End` on success, `Error { terminal: true }`
/// on timeout / panic / executor failure.
fn build_terminal_chunk(inputs: BuildTerminalChunkInputs<'_>) -> ChunkPayload {
    if inputs.timed_out {
        tracing::warn!(
            outlet_id = %inputs.outlet_id,
            code = CODE_EXECUTION_FAULT,
            slug = SLUG_EXECUTION_TIMEOUT,
            timeout_ms = inputs.effective_timeout,
            "outlet streaming executor timed out — emitted terminal Error chunk and dropped task"
        );
        return ChunkPayload::Error {
            code: CODE_EXECUTION_FAULT.to_owned(),
            message: format!(
                "outlet execution timed out after {timeout}ms",
                timeout = inputs.effective_timeout
            ),
            terminal: true,
        };
    }
    match inputs.executor_outcome {
        Some(Ok(Ok(()))) => {
            let execution_time_ms = elapsed_ms(inputs.start);
            ChunkPayload::End {
                aggregate: serde_json::Value::Null,
                provenance: placeholder_data_provenance(inputs.context_id),
                execution_time_ms,
            }
        }
        Some(Ok(Err(exec_err))) => executor_error_to_terminal_payload(&exec_err),
        Some(Err(panic_payload)) => {
            let panic_message = panic_payload_to_message(&panic_payload);
            tracing::warn!(
                outlet_id = %inputs.outlet_id,
                code = CODE_EXECUTION_FAULT,
                slug = SLUG_EXECUTION_HANDLER_PANIC,
                panic_message = %panic_message,
                "outlet streaming executor panicked — recovered via catch_unwind (operator-attributable, §5.4.2)"
            );
            if let Some(sink) = inputs.handler_panic_sink {
                sink.record(handler_panic_event(inputs.outlet_id));
            }
            ChunkPayload::Error {
                code: CODE_EXECUTION_FAULT.to_owned(),
                message: panic_message,
                terminal: true,
            }
        }
        None => {
            // Unreachable in production: the pump only exits without
            // an outcome on timeout, which is handled above.
            ChunkPayload::Error {
                code: CODE_EXECUTION_FAULT.to_owned(),
                message: "executor task aborted before emitting an outcome".to_owned(),
                terminal: true,
            }
        }
    }
}

// ===========================================================================
// Cross-context re-encrypting streaming bridge (SCP-OUT-036)
// ===========================================================================
//
// The best-effort cross-context *outlet stream* crossing the §6.2 boundary
// (§6.2.5; NOT the transactional streaming saga, SCP-OUT-046). The
// shared-member bridge is the human's SDK seam (§6.2.0): the invoker is a
// member of BOTH the operating context B and the receiving context A, so the
// runtime forwards each operator-signed chunk to that invoker IN-PROCESS as
// PLAINTEXT — a sanctioned disclosure mirroring the same-context
// `invoke_outlet` (and the unary saga whose output returns to the invoker as
// bytes while its own log records only a hash, §6.2.4). Re-encryption for A's
// OTHER members is the DELIVERY SEAM, not this return type: the SDK seals each
// still-operator-signed chunk under A's MLS group key over the existing
// §9.8/§9.16 transport. The operator's `SCP-OUTLET-CHUNK-SIG-V1` signature is
// preserved END-TO-END and NEVER re-signed by the bridge, so the per-chunk
// equivocation binding survives the crossing.

use ed25519_dalek::VerifyingKey;
use scp_protocol::context::outlets::OutletKind;
use scp_protocol::context::outlets::error_codes::{
    CODE_AUTHORIZATION_DENIED, CODE_OUTPUT_VIOLATION, CODE_TRANSPORT_FAULT,
    SLUG_AUTHORIZATION_DENIED, SLUG_OUTPUT_SCHEMA_VIOLATION,
    SLUG_TRANSPORT_CROSS_CONTEXT_BRIDGE_FAILURE,
};
use scp_protocol::context::outlets::registration::OutletRegistration;
use scp_protocol::context::outlets::stream::{compute_chunk_manifest_root, verify_chunk_signature};

/// The verification descriptor the cross-context bridge PINS at stream-open
/// and consults for every forwarded chunk (§5.4.5 "Verification source at the
/// crossing").
///
/// Every field is sourced from the governed outlet-interface descriptor /
/// stream-open — the operator's public key from the operating context's
/// registered stream signer, the operating context id (B), the outlet id, and
/// the `caveats_binding` pinned at open. It is **never** rebuilt from values a
/// chunk (or a malicious bridge) supplies at delivery time: a bridge that could
/// substitute the verification inputs could pass off chunks signed by a
/// *different* operator, or for a *different* context it controls, as if they
/// were B's — defeating the per-chunk equivocation binding.
#[derive(Clone)]
pub(crate) struct CrossContextVerificationDescriptor {
    /// The operating context B's operator verifying key (from the pinned
    /// stream signer at open).
    pub(crate) operator_pk: VerifyingKey,
    /// The OPERATING context id (B) — the context whose `context_id` the
    /// operator committed into each chunk-signature preimage.
    pub(crate) operating_context_id: String,
    /// The outlet id committed into each chunk-signature preimage.
    pub(crate) outlet_id: String,
    /// The 32-byte `caveats_binding` pinned at stream-open, committed into
    /// each chunk-signature preimage.
    pub(crate) caveats_binding: [u8; 32],
    /// The 16-byte `request_id` pinned at stream-open — the ONLY `request_id`
    /// whose chunks this crossing forwards (§5.4.5 "Verification source at the
    /// crossing"). The per-chunk preimage commits `request_id`, so the
    /// verification MUST fix it from the governed open — NOT trust the
    /// `request_id` a delivered chunk asserts. Although `caveats_binding`
    /// already commits `request_id` (§5.4.5 binding preimage) and so a chunk
    /// signed for a different stream would fail signature verification against
    /// the pinned `caveats_binding` today, pinning `request_id` explicitly makes
    /// the "never rebuilt from chunk-supplied values" invariant hold on its own
    /// terms — defense-in-depth against any future decoupling of the two
    /// bindings. §5.4.5:570 enumerates `operator_pk` / `context_id` /
    /// `caveats_binding` as the pinned values; `request_id` is not in that list,
    /// so this pin extends the rule's SPIRIT (never trust a delivery-time-
    /// asserted value) to `request_id`, it does not implement the rule verbatim.
    pub(crate) expected_request_id: RequestId,
}

/// Verifies one forwarded chunk's operator signature against the PINNED
/// descriptor (§5.4.5 "Verification source at the crossing"). Returns `true`
/// iff the chunk is genuinely B's operator's for this stream.
///
/// This is the receiver-side crossing analog of §6.2.4's caller-authentication
/// rule: the channel-pinned identity governs, not envelope-asserted fields.
#[must_use]
pub(crate) fn verify_forwarded_chunk(
    descriptor: &CrossContextVerificationDescriptor,
    chunk: &OutletStreamChunk,
) -> bool {
    // Pin `request_id` from the governed open — never trust the value the
    // delivered chunk asserts (§5.4.5 "Verification source at the crossing").
    // A chunk asserting a DIFFERENT `request_id` (even a valid operator
    // signature for another same-outlet stream) is rejected here, so the
    // crossing forwards exactly the stream that was opened.
    if chunk.request_id != descriptor.expected_request_id {
        return false;
    }
    verify_chunk_signature(
        chunk,
        &descriptor.operator_pk,
        &descriptor.operating_context_id,
        &descriptor.outlet_id,
        &descriptor.caveats_binding,
    )
}

/// §5.4.5 "Cross-context economy (best-effort is zero-escrow)" gate.
///
/// The best-effort cross-context bridge serves Query outlets and zero-cost
/// (`cost == None || cost.amount == 0`) Action outlets, propagating the
/// invoker's credit grants end-to-end as backpressure (credit is flow-control,
/// not payment) and performing NO caller-side escrow settlement — which
/// ADR-061 makes saga-unique. A best-effort open of a PAID Action outlet
/// (`cost.amount > 0`) is therefore rejected; a metered paid cross-context
/// stream MUST use the streaming saga (SCP-OUT-046).
///
/// The predicate is the spec's economic predicate (`cost.amount > 0`); a
/// `Query` outlet cannot carry a positive `cost` by registration validation
/// (§5.4.2 query-cost floor), so this is equivalent to "paid Action" while
/// remaining faithful to the spec's cost-only formulation.
///
/// # Split-source hardening (gate the value actually BILLED)
///
/// The zero-escrow invariant must hold on the field that DRIVES billing, not
/// only on the registration's declared `cost`. The B-side reserve /
/// pump bill `cost_per_chunk` (the §19.5 per-billable-chunk pricing unit),
/// which is a SEPARATE caller-supplied field from `registration.cost`. If the
/// gate inspected only `registration.cost` and a caller presented
/// `registration.cost.amount == 0` together with `cost_per_chunk > 0`, the
/// open would pass the "zero-escrow" gate while the pump billed every chunk —
/// a paid stream smuggled through the best-effort (settlement-free) path. So
/// this gate rejects when EITHER the registered cost OR the billed
/// `cost_per_chunk` is positive, and (since both must be zero to proceed) the
/// two can no longer diverge: the value gated is exactly the value billed. The
/// authoritative per-billable-chunk unit for a registered outlet is
/// `registration.cost.amount` (§19.5); a `cost_per_chunk` that disagrees with a
/// zero registered cost is a caller inflating its own bill and is refused.
///
/// # Errors
///
/// Returns [`InvocationError::CrossContextPaidActionUnsupported`] when the
/// registered cost OR the billed `cost_per_chunk` is positive; `Ok(())`
/// otherwise (both zero — the only shape the zero-escrow bridge serves).
pub(crate) fn cross_context_economy_gate(
    registration: &OutletRegistration,
    cost_per_chunk: scp_protocol::economy::types::Amount,
) -> Result<(), InvocationError> {
    let registered_paid = registration
        .cost
        .as_ref()
        .is_some_and(|cost| cost.amount.value() > 0);
    // Gate on the value that actually drives billing, not only the declared
    // registration cost — a zero registered cost with a positive
    // `cost_per_chunk` would otherwise pass the gate while the pump bills.
    let billed_paid = cost_per_chunk.value() > 0;
    if registered_paid || billed_paid {
        return Err(InvocationError::CrossContextPaidActionUnsupported {
            outlet_id: registration.outlet_id.clone(),
        });
    }
    // Reaching here means `registration.cost.amount == 0` AND
    // `cost_per_chunk == 0`: the gated value and the billed value are both zero,
    // so they cannot diverge (the split-source bypass is closed).
    //
    // A positive cost implies `OutletKind::Action` by the §5.4.2 registration
    // floor; assert the invariant so a future registration path that broke it
    // would surface here rather than silently admitting a paid Query.
    debug_assert!(
        registration
            .cost
            .as_ref()
            .is_none_or(|c| c.amount.value() == 0)
            || registration.kind == OutletKind::Action,
        "a positive outlet cost must belong to an Action outlet (§5.4.2 query-cost floor)"
    );
    Ok(())
}

/// Test/fault seam for the §5.4.5 mid-stream bridge-failure path (SCP-OUT-036
/// AC8). Production passes `None`; a probe returning `Some(detail)` for a chunk
/// forces the bridge to emit the transport-fault terminal in that chunk's
/// place, modelling an internal decrypt / re-encrypt / forward / validation
/// infrastructure failure that the best-effort bridge cannot recover.
pub(crate) type BridgeFaultProbe = Box<dyn Fn(&OutletStreamChunk) -> Option<String> + Send>;

/// A forwarded cross-context outlet-stream chunk paired with its per-sender MLS
/// send-sequence anchor (SCP-OUT-044).
///
/// Provenance: §5.4.5 "Ordering and gaps"; §6.2.0 Outlet Interface Transport;
/// ADR-049 §8 `SequenceReservation`.
///
/// The `base_sequence` is the per-sender, strictly-monotone (`+1` per forwarded
/// chunk) MLS send-sequence anchor reserved via the ADR-049 §8
/// [`SequenceReservation`](crate::context::actor::SequenceReservation) guard at
/// the moment the bridge hands the chunk to A's outer channel — the point of
/// consumption the `outlets_helpers` open-time comments defer to. It is exposed
/// as `(request_id, base_sequence)` to the future authoritative reassembly
/// gap-detector (SCP-OUT-045), recoverable as `frame.chunk.request_id` +
/// `frame.base_sequence`.
///
/// This is a RUNTIME-ONLY, in-process wrapper on the bridge's outer channel: it
/// is deliberately NOT a field of the operator-signed
/// [`OutletStreamChunk`](scp_protocol::context::outlets::stream::OutletStreamChunk).
/// Adding a field there would (a) diverge A's independently-recomputed manifest
/// root — `compute_chunk_leaf_hash` JCS-hashes the ENTIRE chunk, and A's
/// verified append (`append_outlet_invoked_verified`) wire-rejects any
/// manifest-root mismatch against B's committed manifest — and (b) change the
/// FFI-conformance wire type. The chunk is carried through byte-for-byte
/// unmodified (operator signature preserved); the anchor rides alongside it.
///
/// Derives `Debug` only: it is never serialized (in-process channel item), which
/// keeps the FFI/serde/protocol-sync surface untouched. Construct via struct
/// literal only (no `new` constructor — cross-layer construction gate).
#[derive(Debug)]
pub struct ForwardedStreamFrame {
    /// Per-sender send-sequence anchor (the §5.4.5 ordering anchor) for the
    /// authoritative cross-context reassembly gap-detector (SCP-OUT-045;
    /// consumed via the SCP-OUT-047 streaming-saga FFI). Reserved-at-consumption
    /// on the cross-context send hop (SCP-OUT-044): 1-based, strictly `+1` per
    /// forwarded chunk, so the detector keys on `(chunk.request_id,
    /// base_sequence)` and flags any missing chunk as a gap.
    ///
    /// This is a GAP-DETECTION ANCHOR, NOT an MLS AEAD sequence input — it is
    /// never fed to any encryption. The A-context re-seal at the SDK delivery
    /// seam (SCP-OUT-047) assigns its OWN MLS send-sequence; feeding THIS value
    /// as an AEAD sequence/nonce there would be a byte-identity regression (see
    /// the AAD warning in the `context::actor::sequence` module). And do NOT
    /// confuse it with `chunk.sequence` (the operator's per-request chunk
    /// index) — the gap-detector keys on this field, never on `chunk.sequence`.
    pub base_sequence: u64,
    /// The operator-signed chunk, forwarded verbatim (never re-signed, never
    /// mutated) — its `request_id` + `sequence` are unchanged.
    pub chunk: OutletStreamChunk,
}

/// Reserve → send → commit a single forwarded chunk under the ADR-049 §8
/// [`SequenceReservation`](crate::context::actor::SequenceReservation) RAII
/// guard (SCP-OUT-044). This is the allocate-at-consumption seam the
/// `outlets_helpers` open-time reservation deliberately defers to.
///
/// The per-sender `base_sequence` is reserved from `send_tracker` (post-increment,
/// 1-based — first reservation returns `1`), stamped onto the
/// [`ForwardedStreamFrame`], and the frame is sent to A's outer channel. The
/// reservation is committed ONLY after the send succeeds; if the send fails (A
/// stopped consuming), the guard is dropped WITHOUT `commit`, so its `Drop`
/// rolls the tracker back — the next allocation reuses the freed number and NO
/// send-sequence gap is burned (§5.15.7 send-sequence reservation: a number
/// becomes durable iff the payload was handed to the transport).
///
/// Returns `true` iff the frame was accepted by the outer channel (A is still
/// consuming); `false` means A stopped — the caller MUST stop forwarding.
#[must_use]
async fn forward_frame(
    outer_tx: &mpsc::Sender<ForwardedStreamFrame>,
    send_tracker: &mut crate::context::actor::SendSequenceTracker,
    chunk: &OutletStreamChunk,
) -> bool {
    let reservation = crate::context::actor::SequenceReservation::reserve(send_tracker);
    let frame = ForwardedStreamFrame {
        base_sequence: reservation.number(),
        chunk: chunk.clone(),
    };
    if outer_tx.send(frame).await.is_err() {
        // A stopped consuming before this frame landed. Dropping `reservation`
        // WITHOUT commit rolls the tracker back (no gap burned).
        return false;
    }
    // The frame reached the transport (A's outer channel) — the sequence is now
    // durable-by-intent; commit so `Drop` does not roll it back.
    reservation.commit();
    true
}

/// Forwards a BRIDGE-SYNTHESIZED terminal chunk (schema violation,
/// signature-verification failure, or mid-stream bridge fault) to A's invoker
/// and folds it into the receiver-side manifest snapshot.
///
/// The bridge never re-signs: a synthesized terminal is NOT operator-authored,
/// so it carries the all-zero signature placeholder (there is no operator
/// equivocation binding to preserve for a chunk the operator never produced).
/// A's manifest commits to exactly the sequence A forwarded. The write-through
/// snapshot is updated only AFTER a successful forward (§6.2.5) — it is a
/// replay snapshot, never a forwarding buffer.
///
/// Returns `true` iff the terminal was DELIVERED to A's invoker (the outer
/// channel accepted it). `false` means A stopped consuming before the terminal
/// landed — the caller MUST NOT synthesize a further terminal onto a closed
/// channel.
#[must_use]
async fn forward_bridge_terminal(
    outer_tx: &mpsc::Sender<ForwardedStreamFrame>,
    send_tracker: &mut crate::context::actor::SendSequenceTracker,
    reassembled: &mut Vec<OutletStreamChunk>,
    terminal: &mut StreamTerminalSummary,
    request_id: RequestId,
    sequence: u64,
    payload: ChunkPayload,
) -> bool {
    let chunk = OutletStreamChunk {
        request_id,
        sequence,
        payload,
        sig: [0u8; 64],
    };
    // Reserve-at-consumption (SCP-OUT-044): the synthesized terminal carries its
    // own per-sender `base_sequence` anchor, allocated + committed on the send
    // hop like every forwarded chunk. A send failure rolls the reservation back.
    if !forward_frame(outer_tx, send_tracker, &chunk).await {
        // A's invoker stopped consuming before the terminal landed — record
        // what was already delivered; the terminal summary keeps its prior
        // (default) status.
        return false;
    }
    // The manifest snapshot commits over the bare `OutletStreamChunk` (never the
    // runtime frame), so B's committed manifest and A's recomputation agree.
    terminal.observe(&chunk.payload);
    reassembled.push(chunk);
    true
}

/// Records the receiving context A's own `OutletInvoked` event at stream close
/// (SCP-OUT-036 AC7; §5.4.5).
///
/// A re-derives the manifest root + billable count over its INDEPENDENTLY
/// reassembled chunk sequence and records through the verified-append boundary
/// [`ContextEventLogProvider::append_outlet_invoked_verified`](crate::context::builder::ContextEventLogProvider::append_outlet_invoked_verified),
/// which WIRE-REJECTS any `chunks_billed` / manifest-root mismatch at
/// log-insert time as `EventLogError::ChunksBilledMismatch` (§5.4.5:566
/// "refused at log-insert time, not accepted-and-flagged"). On the happy path
/// A's derived aggregates match those the operator's B-side pump committed —
/// A recomputes over exactly the chunks B produced and signed — so the append
/// succeeds and both logs carry the SAME 32-byte `stream_manifest_hash`
/// (best-effort, non-atomic dual recording; the atomic guarantee is the
/// streaming saga's, SCP-OUT-046).
#[allow(clippy::too_many_arguments)]
async fn record_cross_context_a_event(
    a_event_log: &std::sync::Arc<dyn crate::context::builder::ContextEventLogProvider>,
    receiving_context_id: &str,
    invoker_did: &DID,
    request_id: RequestId,
    outlet_id: &OutletId,
    input_hash: String,
    execution_time_ms: u64,
    terminal: &StreamTerminalSummary,
    reassembled: &[OutletStreamChunk],
    timestamp_secs: u64,
) {
    let manifest = match compute_chunk_manifest_root(reassembled) {
        Ok(root) => root,
        Err(err) => {
            tracing::error!(
                %err,
                context_id = %receiving_context_id,
                "cross-context bridge: A-side manifest-root computation failed — \
                 skipping A's OutletInvoked recording"
            );
            return;
        }
    };
    let stream_chunk_count = u32::try_from(reassembled.len()).unwrap_or(u32::MAX);
    // The best-effort bridge processes no cross-context `OutletCancel`, so the
    // §5.4.5 billing ceiling is `u64::MAX` and `chunks_billed` reduces to the
    // count of `Data` leaves — identical to the frontier-derived value B's pump
    // committed, so the verified append passes on the happy path.
    let chunks_billed =
        crate::context::outlets::stream::compute_chunks_billed_ref(reassembled, u64::MAX);
    let event = build_streaming_outlet_event(
        request_id,
        outlet_id,
        invoker_did,
        input_hash,
        execution_time_ms,
        stream_chunk_count,
        chunks_billed,
        manifest,
        terminal,
        // The bridge maintains a single retained sequence (no separate running
        // tally to diverge from), and processes no cancel-ack.
        None,
        None,
    );
    if let Err(err) = a_event_log
        .append_outlet_invoked_verified(
            &crate::context::state::context_id_to_bytes(receiving_context_id),
            &event,
            reassembled,
            invoker_did.as_ref(),
            timestamp_secs,
        )
        .await
    {
        // §5.4.5:566 wire-rejection (`ChunksBilledMismatch`) or a persistence
        // fault. The best-effort bridge does not fail the already-drained
        // stream on a receiver-side recording fault — it surfaces the refusal
        // to the audit log (the atomic all-or-nothing dual-log guarantee is the
        // streaming saga's, SCP-OUT-046).
        tracing::error!(
            %err,
            context_id = %receiving_context_id,
            "cross-context bridge: A-side OutletInvoked recording refused at the \
             verified-append boundary (§5.4.5:566)"
        );
    }
}

/// Constructs the onward A-leg [`OutletStreamOpen`] the shared-member SDK seam
/// uses to frame delivery of the re-encrypted stream to the RECEIVING context
/// A's OTHER members (§5.4.5; §6.2.0).
///
/// The A-leg open INHERITS `chain_depth` **verbatim** from the incoming B-side
/// open — the best-effort forwarder never increments or recomputes it
/// (cross-context depth-budget enforcement is the consent gate's job, not this
/// forwarder's), and `chain_depth` is a field of the *open*, NEVER of an
/// [`OutletStreamChunk`] (chunks carry / recompute / check nothing about it, so
/// no forwarded chunk can mutate it). Every other open field is carried through
/// unchanged so the A-leg stream is framed identically to the incoming
/// crossing.
///
/// [`OutletStreamOpen`]: scp_protocol::context::outlets::stream::OutletStreamOpen
#[must_use]
pub(crate) fn build_onward_a_leg_open(
    incoming_open: &scp_protocol::context::outlets::stream::OutletStreamOpen,
) -> scp_protocol::context::outlets::stream::OutletStreamOpen {
    // Identity-carry: the load-bearing invariant is that `chain_depth` is
    // inherited unchanged (no `+1`) onto the onward A-leg open. Cloning the
    // whole open makes that inheritance explicit and total.
    incoming_open.clone()
}

/// Absolute ceiling on the number of chunks the cross-context bridge RETAINS in
/// its §6.2.5 write-through replay snapshot (`reassembled`) for a single stream.
///
/// The snapshot must hold the full chunk sequence to re-derive A's manifest root
/// at close, so it grows with stream length. For a zero-cost / Query best-effort
/// stream (`cost_per_chunk == 0` ⇒ `max_billable == None`) there is NO economic
/// bound on the chunk count, and `Progress` chunks are NEVER billed — so a
/// hostile or buggy operating context B could otherwise flood the bridge task
/// with unbilled chunks and drive A's process to OOM (the outer `mpsc(1)`
/// bounds only the in-flight forward, not the retained snapshot). This absolute
/// ceiling bounds the retained snapshot regardless of chunk type; on breach the
/// bridge forwards a transport-fault terminal (`SCP-OUTLET-6160`) and stops.
///
/// The value (`1 << 20` = 1,048,576) is chosen to sit far above any legitimate
/// best-effort stream while bounding the per-stream retained memory to a finite
/// envelope. It is a SAFE default the review did not pin numerically; a paid,
/// unbounded-length metered stream is the streaming saga's domain (SCP-OUT-046),
/// not this best-effort bridge.
pub(crate) const MAX_CROSS_CONTEXT_STREAM_CHUNKS: usize = 1 << 20;

/// The off-mailbox bridge task body (SCP-OUT-036).
///
/// Consumes B's plaintext operator-signed chunks (`inner_rx`), verifies each
/// against the PINNED descriptor, validates Data/End against the outlet's
/// schemas, forwards each chunk UNMODIFIED (signature preserved) to A's invoker
/// over a bounded outer channel, and at close records A's own `OutletInvoked`
/// event over the independently reassembled sequence.
///
/// No bridge-level buffering: each chunk is forwarded as produced, subject to
/// the outer channel's backpressure (bounded to 1 so chunk N is delivered
/// before chunk N+1 is pulled from the source). The retained `reassembled`
/// vector is the §6.2.5 write-through replay snapshot used to re-derive A's
/// manifest — it is populated only AFTER each successful forward and never
/// gates delivery.
///
/// `governing_chain_depth` is the A-leg open's inherited `chain_depth` (§5.4.5
/// "`chain_depth` … governs the whole stream"); it is carried here for the
/// bridge's diagnostics — it is a property of the open, never of a chunk.
///
/// `max_retained_chunks` bounds the retained `reassembled` snapshot (see
/// [`MAX_CROSS_CONTEXT_STREAM_CHUNKS`]) — production passes that const; the tests
/// pass a small value to exercise the cap.
///
/// # Terminal guarantee (§5.4.5)
///
/// A's stream ALWAYS closes on a terminal chunk. Beyond the operator's own
/// terminal (`End` / `Error { terminal }`) and the three synthesized fault
/// terminals (sig reject, bridge fault, schema violation), the loop guards two
/// more paths that would otherwise truncate A after a non-terminal `Data`:
/// - the operating context B drops its sender WITHOUT a terminal chunk (e.g. an
///   operator-signer failure at the terminal chunk collapses the pump's
///   producer to `None`) — synthesized as a `SCP-OUTLET-6160` transport fault;
/// - the retained snapshot reaches `max_retained_chunks` (an unbilled-chunk
///   flood `DoS`) — also a `SCP-OUTLET-6160` transport fault.
///
/// The post-loop synthesis fires only when NO terminal was delivered AND the
/// outer channel is still open (A is still consuming), so A never receives two
/// terminals and never sees a synthesized terminal on a channel it abandoned.
#[allow(clippy::too_many_arguments)]
// One cohesive forward-loop over shared `reassembled` / `terminal` /
// `execution_time_ms` / `delivered_terminal` / `outer_open` state with several
// break-and-record exits (chunk-cap, sig reject, bridge fault, schema violation,
// operator terminal, consumer-gone) plus a post-loop terminal-guarantee
// synthesis; splitting it would thread that mutable state and the break signal
// through a helper, obscuring the §5.4.5 ordering.
#[allow(clippy::too_many_lines)]
pub(crate) async fn run_cross_context_bridge(
    mut inner_rx: mpsc::Receiver<OutletStreamChunk>,
    outer_tx: mpsc::Sender<ForwardedStreamFrame>,
    descriptor: CrossContextVerificationDescriptor,
    output_schema: serde_json::Value,
    aggregate_schema: Option<serde_json::Value>,
    a_event_log: std::sync::Arc<dyn crate::context::builder::ContextEventLogProvider>,
    receiving_context_id: String,
    invoker_did: DID,
    request_id: RequestId,
    outlet_id: OutletId,
    input_hash: String,
    governing_chain_depth: u8,
    timestamp_secs: u64,
    max_retained_chunks: usize,
    fault_probe: Option<BridgeFaultProbe>,
) {
    tracing::debug!(
        chain_depth = governing_chain_depth,
        request_id = %hex::encode(request_id),
        context_id = %receiving_context_id,
        "cross-context bridge: forwarding B→A under the governing chain_depth (§5.4.5)"
    );
    let mut reassembled: Vec<OutletStreamChunk> = Vec::new();
    let mut terminal = StreamTerminalSummary::default();
    // Per-sender MLS send-sequence allocator for THIS cross-context send hop
    // (SCP-OUT-044). Task-scoped (one per bridged stream), so it resolves the
    // request-scope objection the actor's LIFO `rollback_sequence_number` cannot
    // (the off-mailbox bridge cannot reach the actor's `PerContextState`
    // `send_tracker` under ADR-049 isolation). Every chunk forwarded to A —
    // operator-authored or synthesized — draws its `base_sequence` from here via
    // the ADR-049 §8 `SequenceReservation` guard.
    let mut send_tracker = crate::context::actor::SendSequenceTracker::new();
    let mut execution_time_ms: u64 = 0;
    // Terminal-guarantee bookkeeping: `delivered_terminal` becomes true once a
    // terminal chunk (operator-authored or synthesized) is DELIVERED to A;
    // `outer_open` becomes false once A stops consuming. The post-loop synthesis
    // fires iff `!delivered_terminal && outer_open`.
    let mut delivered_terminal = false;
    let mut outer_open = true;

    while let Some(chunk) = inner_rx.recv().await {
        // (FIX 4) Bound the retained write-through snapshot: a hostile B flooding
        // unbilled `Progress` chunks cannot grow `reassembled` past the cap and
        // OOM the bridge task. On breach, forward a §5.4.5 transport-fault
        // terminal and stop rather than retaining another chunk.
        if reassembled.len() >= max_retained_chunks {
            let payload = ChunkPayload::Error {
                code: CODE_TRANSPORT_FAULT.to_owned(),
                message: format!(
                    "{SLUG_TRANSPORT_CROSS_CONTEXT_BRIDGE_FAILURE}: cross-context stream exceeded \
                     the retained-chunk ceiling ({max_retained_chunks}) — terminating (§5.4.5)"
                ),
                terminal: true,
            };
            let next_seq = reassembled
                .last()
                .map_or(chunk.sequence, |c| c.sequence.saturating_add(1));
            delivered_terminal = forward_bridge_terminal(
                &outer_tx,
                &mut send_tracker,
                &mut reassembled,
                &mut terminal,
                request_id,
                next_seq,
                payload,
            )
            .await;
            outer_open = delivered_terminal;
            break;
        }

        // (AC11) Verify the operator signature against the PINNED descriptor —
        // NEVER against bridge-supplied values (§5.4.5 "Verification source at
        // the crossing"). A mismatch (bad signature OR a chunk asserting a
        // `request_id` other than the pinned one) is a §5.4.5
        // chunk-signature-verification failure: emit an Authorization-class
        // terminal and stop.
        if !verify_forwarded_chunk(&descriptor, &chunk) {
            let payload = ChunkPayload::Error {
                code: CODE_AUTHORIZATION_DENIED.to_owned(),
                message: format!(
                    "{SLUG_AUTHORIZATION_DENIED}: operator chunk signature failed verification \
                     against the pinned outlet-interface descriptor (§5.4.5)"
                ),
                terminal: true,
            };
            delivered_terminal = forward_bridge_terminal(
                &outer_tx,
                &mut send_tracker,
                &mut reassembled,
                &mut terminal,
                request_id,
                chunk.sequence,
                payload,
            )
            .await;
            outer_open = delivered_terminal;
            break;
        }

        // (AC8) Injected / internal bridge fault (decrypt / re-encrypt /
        // forward / validation infrastructure failure) → §5.4.5 transport-fault
        // terminal (`SCP-OUTLET-6160`, `transport.cross-context-bridge-failure`).
        if let Some(detail) = fault_probe.as_ref().and_then(|probe| probe(&chunk)) {
            let payload = ChunkPayload::Error {
                code: CODE_TRANSPORT_FAULT.to_owned(),
                message: format!("{SLUG_TRANSPORT_CROSS_CONTEXT_BRIDGE_FAILURE}: {detail}"),
                terminal: true,
            };
            delivered_terminal = forward_bridge_terminal(
                &outer_tx,
                &mut send_tracker,
                &mut reassembled,
                &mut terminal,
                request_id,
                chunk.sequence,
                payload,
            )
            .await;
            outer_open = delivered_terminal;
            break;
        }

        // Schema validation: `Data.value` against `output_schema`;
        // `End.aggregate` against `aggregate_schema` when the outlet registered
        // one, ELSE against `output_schema` (§5.4.5 ChunkPayload). `Progress`
        // and `Error` pass through unvalidated.
        let schema_violation: Option<String> = match &chunk.payload {
            ChunkPayload::Data { value } => {
                validate_value_against_schema(value, &output_schema).err()
            }
            ChunkPayload::End { aggregate, .. } => {
                let effective_schema = aggregate_schema.as_ref().unwrap_or(&output_schema);
                validate_value_against_schema(aggregate, effective_schema).err()
            }
            ChunkPayload::Progress { .. } | ChunkPayload::Error { .. } => None,
        };
        if let Some(message) = schema_violation {
            // (AC5 / AC9) Data or End schema violation → terminal Output
            // violation (`SCP-OUTLET-6140`). Forward the terminal in the
            // offending chunk's place, then stop (ordering preserved: the valid
            // prefix was already forwarded; the invalid chunk is replaced).
            let payload = ChunkPayload::Error {
                code: CODE_OUTPUT_VIOLATION.to_owned(),
                message: format!("{SLUG_OUTPUT_SCHEMA_VIOLATION}: {message}"),
                terminal: true,
            };
            delivered_terminal = forward_bridge_terminal(
                &outer_tx,
                &mut send_tracker,
                &mut reassembled,
                &mut terminal,
                request_id,
                chunk.sequence,
                payload,
            )
            .await;
            outer_open = delivered_terminal;
            break;
        }

        // Capture End's summed wall-clock elapsed for A's event.
        if let ChunkPayload::End {
            execution_time_ms: end_elapsed,
            ..
        } = &chunk.payload
        {
            execution_time_ms = *end_elapsed;
        }

        // (AC3) Forward as produced — no buffering. The operator signature is
        // preserved verbatim (never re-signed). Each forward reserves + commits
        // a per-sender `base_sequence` anchor at consumption (SCP-OUT-044) via
        // the ADR-049 §8 `SequenceReservation` guard; a send failure rolls the
        // reservation back so no send-sequence gap is burned. Push to the
        // write-through replay snapshot only AFTER a successful forward (§6.2.5)
        // — never before, so the retained vector can never gate delivery, and
        // the manifest commits over the bare `OutletStreamChunk` (not the frame).
        let is_terminal = chunk.payload.is_terminal();
        if !forward_frame(&outer_tx, &mut send_tracker, &chunk).await {
            // A's invoker stopped consuming — stop forwarding and record what
            // was already delivered.
            outer_open = false;
            break;
        }
        terminal.observe(&chunk.payload);
        reassembled.push(chunk);
        if is_terminal {
            delivered_terminal = true;
            break;
        }
    }

    // (FIX 3) Terminal guarantee: if the loop ended WITHOUT delivering any
    // terminal — B's pump dropped its sender without emitting one (e.g. an
    // operator-signer failure collapsed `try_build_signed_chunk` to `None` at
    // the terminal chunk) — and A is still consuming, synthesize a
    // transport-fault terminal so A never truncates after a non-terminal `Data`
    // while recording a default `Error` terminal.
    if !delivered_terminal && outer_open {
        let payload = ChunkPayload::Error {
            code: CODE_TRANSPORT_FAULT.to_owned(),
            message: format!(
                "{SLUG_TRANSPORT_CROSS_CONTEXT_BRIDGE_FAILURE}: operating context closed the \
                 stream without a terminal chunk (§5.4.5)"
            ),
            terminal: true,
        };
        let next_seq = reassembled
            .last()
            .map_or(0, |c| c.sequence.saturating_add(1));
        let _ = forward_bridge_terminal(
            &outer_tx,
            &mut send_tracker,
            &mut reassembled,
            &mut terminal,
            request_id,
            next_seq,
            payload,
        )
        .await;
    }

    // (AC7) A-side recording through the verified-append boundary.
    record_cross_context_a_event(
        &a_event_log,
        &receiving_context_id,
        &invoker_did,
        request_id,
        &outlet_id,
        input_hash,
        execution_time_ms,
        &terminal,
        &reassembled,
        timestamp_secs,
    )
    .await;
}

/// The transactional streaming-saga seal task (SCP-OUT-046 #134; the ADR-061
/// seal phase). The off-mailbox sibling of [`run_cross_context_bridge`]: it
/// owns B's operator-signed chunk receiver + the caller's outer channel, runs
/// the SAME §5.4.5 crossing gates (verify against the pinned descriptor →
/// schema-validate → forward), but instead of the best-effort A-side manifest
/// reassembly it drives the SAGA seal:
///
/// - After each successfully-forwarded operator chunk it sends
///   [`SagaPhaseMessage::StreamCaptureAppend`] to the target (B) actor, folding
///   the chunk into the DURABLE `SagaId`-keyed Merkle frontier staged at
///   Prepare-B (the O(log n) replay snapshot the seal reads to finalize the
///   manifest root). Forwarding is NEVER gated on the capture persist (§6.2.5):
///   the chunk is delivered first, captured second.
/// - At stream-close it sends [`SagaPhaseMessage::CommitBStreamSettle`] ONCE
///   (AC8 — commit once over the bounded root, never a per-chunk 2PC): the B
///   actor seals `stream_manifest_hash = frontier.root()`, signs the streaming
///   receipt (SCP-OUT-043), settles the escrow from the durable ledger, appends
///   B's `OutletInvoked`, and durably captures the replay witness.
///
/// On a successful seal the open-failure `escrow_ticket` is `consume`d (its hold
/// stays reserved through the pump per AC3; the durable ledger owns the billed /
/// refund split the seal recorded) and the saga journal is resolved to
/// `Committed`. On a seal FAILURE the ticket is dropped so its `Drop` reverses
/// the open-time hold, and the journal is LEFT at `Committing` for the
/// autonomous crash-recovery sweep (SCP-OUT-046 #136).
///
/// The receiving-context A-side `CrossContextOutletInvoked` dual-log leaf
/// (SCP-OUT-046 #135) is recorded from the `reassembled` sequence this task
/// accumulates; that recording is wired in the next slice and its seam is marked
/// below. This task never re-signs a chunk and never re-invokes the outlet.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn run_streaming_saga_seal_task(
    supervisor: std::sync::Arc<crate::context::supervisor::Supervisor>,
    target_context_hex: String,
    saga_id: crate::context::supervisor::saga_journal::SagaId,
    target_signing_key: crate::context::actor::commands::SigningKeyBytes,
    // The reservation's spawn-generation (SCP-OUT-046) — passed to
    // `settle_outlet_stream_via_actor` so the close-time settlement is dropped
    // if B respawned between reserve and seal (the same confused-deputy guard
    // the same-context settlement sink holds).
    settlement_generation: u64,
    mut inner_rx: mpsc::Receiver<OutletStreamChunk>,
    outer_tx: mpsc::Sender<ForwardedStreamFrame>,
    escrow_ticket: crate::context::outlets::dispatch::StreamEscrowTicket,
    descriptor: CrossContextVerificationDescriptor,
    output_schema: serde_json::Value,
    aggregate_schema: Option<serde_json::Value>,
    // The RECEIVING context A's shared event-log provider (SCP-OUT-046 #135) —
    // where the A-side `CrossContextOutletInvoked` dual-log leaf is recorded at
    // seal-close, completing the atomic dual-log (B's `OutletInvoked` is
    // recorded by the seal handler).
    a_event_log: std::sync::Arc<dyn crate::context::builder::ContextEventLogProvider>,
) {
    use crate::context::actor::ContextCommand;
    use crate::context::actor::commands::SagaPhaseMessage;

    tracing::debug!(
        saga_id = %saga_id.0,
        request_id = %hex::encode(descriptor.expected_request_id),
        context_id = %target_context_hex,
        "streaming-saga seal task: forwarding B→A + durable frontier capture (ADR-061)"
    );

    // The forwarded sequence (operator chunks + any synthesized terminal),
    // retained for the receiving-context A-side `CrossContextOutletInvoked`
    // recording (SCP-OUT-046 #135, wired next slice). B's DURABLE manifest is the
    // `SagaId`-keyed frontier folded via `StreamCaptureAppend`, NOT this Vec.
    let mut reassembled: Vec<OutletStreamChunk> = Vec::new();
    let mut terminal = StreamTerminalSummary::default();
    // Per-sender MLS send-sequence allocator for THIS send hop (SCP-OUT-044) —
    // task-scoped, exactly as `run_cross_context_bridge` (the off-mailbox seal
    // cannot reach the actor's `send_tracker` under ADR-049 isolation).
    let mut send_tracker = crate::context::actor::SendSequenceTracker::new();
    let mut delivered_terminal = false;
    let mut outer_open = true;
    // `true` once a durable-frontier fold or the seal itself observes the target
    // actor is unreachable / diverged — the seal then closes over the durable
    // prefix (a well-defined truncated close; the journal stays `Committing` so
    // crash recovery reconciles). Set only on the actor-mailbox error paths.
    let mut capture_broke = false;

    while let Some(chunk) = inner_rx.recv().await {
        // Verify the operator signature against the PINNED descriptor (§5.4.5
        // "Verification source at the crossing") — never against chunk-asserted
        // values. A mismatch is an Authorization-class terminal.
        if !verify_forwarded_chunk(&descriptor, &chunk) {
            let payload = ChunkPayload::Error {
                code: CODE_AUTHORIZATION_DENIED.to_owned(),
                message: format!(
                    "{SLUG_AUTHORIZATION_DENIED}: operator chunk signature failed verification \
                     against the pinned outlet-interface descriptor (§5.4.5)"
                ),
                terminal: true,
            };
            delivered_terminal = forward_bridge_terminal(
                &outer_tx,
                &mut send_tracker,
                &mut reassembled,
                &mut terminal,
                descriptor.expected_request_id,
                chunk.sequence,
                payload,
            )
            .await;
            outer_open = delivered_terminal;
            break;
        }

        // Schema validation: `Data.value` against `output_schema`; `End.aggregate`
        // against `aggregate_schema` (else `output_schema`). `Progress` / `Error`
        // pass through unvalidated. A violation forwards a terminal in the
        // offending chunk's place, then stops (the valid prefix already forwarded
        // + captured is what the seal attests).
        let schema_violation: Option<String> = match &chunk.payload {
            ChunkPayload::Data { value } => {
                validate_value_against_schema(value, &output_schema).err()
            }
            ChunkPayload::End { aggregate, .. } => {
                let effective_schema = aggregate_schema.as_ref().unwrap_or(&output_schema);
                validate_value_against_schema(aggregate, effective_schema).err()
            }
            ChunkPayload::Progress { .. } | ChunkPayload::Error { .. } => None,
        };
        if let Some(message) = schema_violation {
            let payload = ChunkPayload::Error {
                code: CODE_OUTPUT_VIOLATION.to_owned(),
                message: format!("{SLUG_OUTPUT_SCHEMA_VIOLATION}: {message}"),
                terminal: true,
            };
            delivered_terminal = forward_bridge_terminal(
                &outer_tx,
                &mut send_tracker,
                &mut reassembled,
                &mut terminal,
                descriptor.expected_request_id,
                chunk.sequence,
                payload,
            )
            .await;
            outer_open = delivered_terminal;
            break;
        }

        // Forward as produced — no buffering, operator signature preserved
        // verbatim (SCP-OUT-044 reserve-at-consumption). A send failure means the
        // caller stopped consuming: stop forwarding, seal over the durable prefix.
        let is_terminal = chunk.payload.is_terminal();
        if !forward_frame(&outer_tx, &mut send_tracker, &chunk).await {
            outer_open = false;
            break;
        }

        // Durable capture: fold the just-forwarded operator chunk into B's
        // `SagaId`-keyed frontier (§6.2.5 replay snapshot; Class-S KEEP monotonic
        // credit). Forwarding already happened — the capture never gates delivery.
        // A vanished/diverged actor closes the seal over the durable prefix.
        let Some(actor) = supervisor.lookup(&target_context_hex) else {
            capture_broke = true;
            outer_open = false;
            break;
        };
        let capture_chunk = chunk.clone();
        let capture_saga_id = saga_id.clone();
        match actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::StreamCaptureAppend {
                    saga_id: capture_saga_id,
                    chunk: Box::new(capture_chunk),
                    reply,
                })
            })
            .await
        {
            Ok(()) => {}
            Err(err) => {
                tracing::error!(
                    saga_id = %saga_id.0,
                    %err,
                    "streaming-saga seal task: durable StreamCaptureAppend failed — \
                     sealing over the durable prefix"
                );
                capture_broke = true;
                outer_open = false;
                break;
            }
        }

        terminal.observe(&chunk.payload);
        reassembled.push(chunk);
        if is_terminal {
            delivered_terminal = true;
            break;
        }
    }

    // Terminal guarantee: B's pump dropped its sender without a terminal AND the
    // caller is still consuming — synthesize a transport-fault terminal so the
    // caller never truncates after a non-terminal `Data`.
    if !delivered_terminal && outer_open && !capture_broke {
        let payload = ChunkPayload::Error {
            code: CODE_TRANSPORT_FAULT.to_owned(),
            message: format!(
                "{SLUG_TRANSPORT_CROSS_CONTEXT_BRIDGE_FAILURE}: operating context closed the \
                 stream without a terminal chunk (§5.4.5)"
            ),
            terminal: true,
        };
        let next_seq = reassembled
            .last()
            .map_or(0, |c| c.sequence.saturating_add(1));
        let _ = forward_bridge_terminal(
            &outer_tx,
            &mut send_tracker,
            &mut reassembled,
            &mut terminal,
            descriptor.expected_request_id,
            next_seq,
            payload,
        )
        .await;
    }

    // Seal the durable frontier ONCE (AC8). The B actor finalizes the manifest
    // root, signs the SCP-OUT-043 streaming receipt under the target's Active
    // Signing Key, settles the escrow from the durable ledger, appends B's
    // `OutletInvoked`, and durably captures the replay witness. `cancel_ack_seq`
    // is `None` — this task processes no cross-context `OutletCancel` (the pump
    // already drops above-cancel-ack `Data`, so the frontier reflects the correct
    // §5.4.5 billing boundary).
    let terminal_status = terminal.terminal_status.clone();
    let seal_result = match supervisor.lookup(&target_context_hex) {
        Some(actor) => {
            let settle_saga_id = saga_id.clone();
            actor
                .send(move |reply| {
                    ContextCommand::SagaPhase(SagaPhaseMessage::CommitBStreamSettle {
                        saga_id: settle_saga_id,
                        terminal_status,
                        cancel_ack_seq: None,
                        target_signing_key,
                        reply,
                    })
                })
                .await
        }
        None => Err(scp_protocol::context::ContextError::ContextNotRegistered(
            format!(
                "streaming-saga seal task: target context '{target_context_hex}' is no longer a \
                 co-resident actor at seal-close — journal left Committing for crash recovery"
            ),
        )),
    };

    match seal_result {
        Ok(outcome) => {
            // The seal committed: the durable ledger owns the billed / refund
            // split (`outcome.billed` / `outcome.refund`), so the open-failure
            // guard must NOT reverse the hold. Consume it (mirrors the
            // same-context open's consume-on-`Ok`).
            escrow_ticket.consume();
            tracing::debug!(
                saga_id = %saga_id.0,
                billed = outcome.billed.value(),
                refund = outcome.refund.value(),
                billed_count = outcome.billed_count,
                stream_chunk_count = outcome.stream_chunk_count,
                manifest_root = %hex::encode(outcome.stream_manifest_hash),
                "streaming-saga seal task: sealed — Committing→Committed"
            );
            // #135 — record the receiving-context (A) `CrossContextOutletInvoked`
            // dual-log leaf, completing the atomic dual-log (B's `OutletInvoked`
            // was recorded by the seal handler). Recorded BEFORE the settlement
            // move below so it borrows the whole `outcome`. Uses the SEALED root
            // from `outcome` (never a re-derivation) + the convergent
            // timestamp/nonce/context-ids from the signed receipt, so every
            // honest member's leaf is byte-identical. `reassembled` is no longer
            // needed — B's durable frontier is the authoritative manifest.
            record_streaming_saga_a_event(&a_event_log, &saga_id, &outcome).await;

            // Apply the ACTUAL budget movement (SCP-OUT-046): the seal handler
            // built the complete `StreamSettlement` from the durable ledger but
            // CANNOT dispatch to its own actor mailbox (re-entrant deadlock), so
            // the off-mailbox seal task applies it here — the escrow refund is
            // credited, the billed `PaymentReceipt` captured, and the §7.3.8
            // cumulative counter released by exactly the billed spend. `None` on
            // a replay (the money already moved). A zero-cost / Query stream
            // still settles (refund = billed = 0; no payment fabricated).
            if let Some(settlement) = outcome.settlement
                && let Err(err) = supervisor
                    .settle_outlet_stream_via_actor(*settlement, settlement_generation)
                    .await
            {
                tracing::error!(
                    saga_id = %saga_id.0,
                    %err,
                    "streaming-saga seal task: close-time escrow settlement failed — the \
                     crash-recovery sweep reconciles the durable reserve"
                );
            }

            // Resolve the journal to `Committed` so crash recovery does not
            // redrive a completed saga. Non-secret (the streaming saga journals
            // public metadata only).
            if let Err(err) = supervisor.resolve_saga_committed(&saga_id).await {
                tracing::error!(
                    saga_id = %saga_id.0,
                    %err,
                    "streaming-saga seal task: journal resolve-to-Committed failed — the crash \
                     recovery sweep will reconcile from the durable committed witness"
                );
            }
        }
        Err(err) => {
            // The seal did not commit. Drop the ticket so its `Drop` reverses the
            // open-time hold (the sole refund path when no seal ran). Leave the
            // journal at `Committing` — the autonomous crash-recovery sweep
            // (SCP-OUT-046 #136) resolves it (witness present → Committed; absent
            // → the key-bearing truncated close, or an honest NeedsRepair).
            drop(escrow_ticket);
            tracing::error!(
                saga_id = %saga_id.0,
                %err,
                "streaming-saga seal task: CommitBStreamSettle failed — open-time escrow hold \
                 reversed, journal left Committing for crash recovery"
            );
        }
    }
}

/// Record the receiving-context (A) `CrossContextOutletInvoked` dual-log leaf at
/// a streaming-saga seal-close (SCP-OUT-046 #135; the streaming sibling of the
/// unary saga's caller-side `cross_context_invoked_leaf`). Shared by the seal
/// task AND the key-bearing crash-recovery truncated close (#136) so both record
/// the identical A-side leaf.
///
/// The leaf is a commit-ordered CONVERGENT durable leaf (ADR-011 Amendment §6
/// carve-out): every field is derived from the SIGNED streaming receipt
/// (`outcome.receipt`) + the SEALED root (`outcome.stream_manifest_hash`) — never
/// a re-derivation over a locally reassembled sequence and never a local clock —
/// so every honest member reconstructs the byte-identical leaf. The convergent
/// timestamp is `receipt.timestamp_ms / 1000` (B's staged `recorded_timestamp_ms`),
/// the SAME instant B's `OutletInvoked` leaf hashes, so the two `nonce`-joined
/// records date the one provenance edge identically (§6.2.4 "Dual event-log
/// recording"; §7.3.1 / §9.9.3).
///
/// Best-effort append (mirrors `record_cross_context_a_event`): the atomic seal
/// guarantee is the durable `xctx_committed_stream_outputs` witness + the journal,
/// so a receiver-side recording fault surfaces to the audit log rather than
/// un-committing the sealed saga. Never re-signs, never re-invokes.
pub(crate) async fn record_streaming_saga_a_event(
    a_event_log: &std::sync::Arc<dyn crate::context::builder::ContextEventLogProvider>,
    saga_id: &crate::context::supervisor::saga_journal::SagaId,
    outcome: &crate::context::actor::commands::CommitBStreamSettleOutcome,
) {
    let receipt: scp_protocol::context::outlets::cross_context_saga::CrossContextOutletStreamReceipt =
        match serde_json::from_slice(&outcome.receipt) {
            Ok(r) => r,
            Err(err) => {
                tracing::error!(
                    saga_id = %saga_id.0,
                    %err,
                    "streaming-saga A-side record: sealed receipt could not be parsed for the \
                     convergent timestamp/nonce — skipping CrossContextOutletInvoked"
                );
                return;
            }
        };
    // The A-side leaf carries the SEALED manifest root (never the unary
    // `output_hash`) + the streaming counters, joined to B's `OutletInvoked` by
    // the shared `nonce`. The context id the leaf lands in is A
    // (`receipt.caller_context_id`); it REFERENCES B (`receipt.target_context_id`).
    let payload = serde_json::json!({
        "saga_id": saga_id.0,
        "target_context_id": hex::encode(receipt.target_context_id),
        "nonce": hex::encode(receipt.nonce),
        "outlet_registration_id": receipt.outlet_registration_id,
        "outlet_invoked_event_id": receipt.outlet_invoked_event_id,
        "stream_manifest_hash": hex::encode(outcome.stream_manifest_hash),
        "chunks_billed": outcome.billed_count,
        "stream_chunk_count": outcome.stream_chunk_count,
        "receipt_len": outcome.receipt.len(),
    });
    let payload_bytes = match serde_json::to_vec(&payload) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(
                saga_id = %saga_id.0,
                %err,
                "streaming-saga A-side record: CrossContextOutletInvoked payload serialization \
                 failed — skipping"
            );
            return;
        }
    };
    if let Err(err) = a_event_log
        .append_context_event_with_payload(
            &receipt.caller_context_id,
            scp_event_log::EventType::CrossContextOutletInvoked,
            &receipt.caller_did,
            scp_event_log::EventPayload {
                data: payload_bytes,
            },
            receipt.timestamp_ms / 1000,
        )
        .await
    {
        tracing::error!(
            saga_id = %saga_id.0,
            %err,
            "streaming-saga A-side record: CrossContextOutletInvoked append failed — the sealed \
             witness remains the authoritative dual-record source"
        );
    }
}

/// Best-effort cross-context re-encrypting streaming bridge (SCP-OUT-036).
///
/// Opens the outlet stream in the OPERATING context B (via the supervisor's
/// escrow-reserve → off-mailbox pump → durable B-side `OutletInvoked` sink
/// path — B's log is recorded by that path, never double-recorded here),
/// takes B's plaintext operator-signed chunk receiver, and spawns the
/// off-mailbox bridge task that forwards each chunk to the shared-member
/// invoker and records the RECEIVING context A's own `OutletInvoked` at close.
/// Returns A's PLAINTEXT `mpsc::Receiver<ForwardedStreamFrame>` in-process to the
/// shared-member invoker (a member of BOTH contexts, §6.2.0) — mirroring the
/// same-context [`invoke_outlet`]. Each [`ForwardedStreamFrame`] pairs the
/// unmodified operator-signed chunk with the per-sender MLS `base_sequence`
/// anchor allocated at consumption on this send hop (SCP-OUT-044), exposed as
/// `(request_id, base_sequence)` to the SCP-OUT-045 gap-detector. Re-encryption
/// for A's OTHER members is the delivery seam (the SDK seals each
/// still-operator-signed `frame.chunk` under A's MLS group key), NOT this return
/// type.
///
/// Zero-escrow (§5.4.5 "Cross-context economy"; ADR-061): a paid Action outlet
/// (`cost.amount > 0`) is rejected BEFORE any stream is opened and NO receiver
/// is produced; Query and zero-cost Action proceed with the invoker's credit
/// grants propagating end-to-end as backpressure. A metered paid cross-context
/// stream MUST use the streaming saga (SCP-OUT-046).
///
/// This is a `pub(crate)` runtime seam reached through
/// [`Supervisor::open_outlet_stream_cross_context`](crate::context::supervisor::Supervisor::open_outlet_stream_cross_context)
/// — no FFI export (SCP-OUT-047).
///
/// # §7.3.8 value-caveat enforcement
///
/// `caveat_binding` is the validated-narrowed [`InvocationCaveatBinding`]
/// (`effective_caveats` + `ucan_cid`) bound to the invocation UCAN. It is
/// threaded verbatim into `open_outlet_stream`, where it drives the §7.3.8
/// post-input hook AND the durable cross-invocation counter reservation
/// (`max_calls` / `amount_max_cumulative` / `rate_window` CAS). When it is
/// `Some`, a single-use (`max_calls: 1`) or amount-capped delegation is
/// enforced ACROSS opens — a second cross-context open on an exhausted counter
/// is rejected. When it is `None`, no §7.3.8 value-caveat gate runs (parity
/// with the non-streaming free path); the caller (FFI / SCP-OUT-047) supplies
/// `Some` for a UCAN carrying value caveats. Note that `params.caveats` /
/// `params.ucan_cid` alone bound only the per-stream chunk ceiling
/// (estimate coercion + `max_billable`) — they do NOT run the value-caveat
/// gate; that runs iff `caveat_binding` is `Some`.
///
/// # Errors
///
/// Returns [`InvocationError`]:
/// - [`OutletNotFound`](InvocationError::OutletNotFound) — the outlet is not in
///   B's registry.
/// - [`CrossContextPaidActionUnsupported`](InvocationError::CrossContextPaidActionUnsupported)
///   — a paid Action outlet OR a positive billed `cost_per_chunk` (zero-escrow
///   rejection on the value actually billed).
/// - the mapped B-side open rejection
///   ([`OpenStreamRejection::to_invocation_error`](crate::context::outlets::dispatch::OpenStreamRejection::to_invocation_error)),
///   including a §7.3.8 counter-CAS rejection when `caveat_binding`'s cap is
///   exhausted.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn invoke_outlet_cross_context<E>(
    supervisor: &std::sync::Arc<crate::context::supervisor::Supervisor>,
    a_event_log: std::sync::Arc<dyn crate::context::builder::ContextEventLogProvider>,
    receiving_context_id: &str,
    operating_context_id: &str,
    registry: &OutletRegistry,
    outlet_id: &OutletId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: std::sync::Arc<E>,
    incoming_open: &scp_protocol::context::outlets::stream::OutletStreamOpen,
    // §7.3.8 validated-narrowed value-caveat binding (`effective_caveats` +
    // `ucan_cid`). `Some` ⇒ the durable value-caveat counter CAS runs at the
    // B-side open; `None` ⇒ no value-caveat gate (parity with the non-streaming
    // free path). Distinct from `params.identity.caveats_binding`, the 32-byte
    // `[u8; 32]` chunk-signature binding.
    caveat_binding: Option<crate::context::outlets_helpers::InvocationCaveatBinding>,
    params: crate::context::outlets::dispatch::OpenStreamParams,
) -> Result<mpsc::Receiver<ForwardedStreamFrame>, InvocationError>
where
    E: OutletExecutor + ?Sized + 'static,
{
    // Look up the registration in B's registry: the economy gate reads its
    // `cost`, and the pinned verification descriptor + schemas are sourced from
    // it BEFORE the stream opens (never from delivery-time chunk input).
    let registration = registry
        .get(outlet_id)
        .ok_or_else(|| InvocationError::OutletNotFound {
            outlet_id: outlet_id.clone(),
        })?;

    // (AC12) Zero-escrow economy gate — reject a paid Action outlet OR a
    // positive billed `cost_per_chunk` before any stream / receiver is created.
    // Gating on the billed value (not only the declared registration cost)
    // closes the split-source bypass where `registration.cost == 0` but
    // `cost_per_chunk > 0` would pass the gate while the pump bills.
    cross_context_economy_gate(registration, params.cost_per_chunk)?;

    // (AC4) Build the onward A-leg open — it inherits `chain_depth` verbatim
    // from the incoming B-side open (never incremented by this forwarder). The
    // depth governs the whole A-leg stream and is a property of the open, never
    // of a chunk.
    let a_leg_open = build_onward_a_leg_open(incoming_open);
    let governing_chain_depth = a_leg_open.chain_depth;

    let request_id = params.request_id;
    // Pin the §5.4.5 verification descriptor + validation schemas from the
    // governed registration / stream-open — the operator key from B's pinned
    // stream signer, the operating context id (B), the outlet id, the
    // `caveats_binding` pinned at open, and the `request_id` pinned at open
    // (the only stream this crossing forwards; never trust chunk-asserted
    // `request_id`).
    let descriptor = CrossContextVerificationDescriptor {
        operator_pk: *params.operator_signer.verifying_key(),
        operating_context_id: operating_context_id.to_owned(),
        outlet_id: outlet_id.clone(),
        caveats_binding: params.identity.caveats_binding,
        expected_request_id: request_id,
    };
    let output_schema = registration.schema.output_schema.clone();
    let aggregate_schema = registration.schema.aggregate_schema.clone();
    // A's event log records only the manifest hash + input hash, never chunk
    // plaintext (the streaming parity of the unary saga's `output_hash`-only
    // caller log, §6.2.4). Compute the input hash before `input` is moved.
    let input_hash = sha256_json(&input);

    // Open the B-side stream. `open_outlet_stream` reserves escrow (zero for
    // Query / zero-cost), sources admission caps + timing policy from B's
    // `ContextParams`, wires B's durable `OutletInvoked` sink internally, and
    // spawns the off-mailbox pump. A best-effort open passes `None` for the
    // three test-capture sinks (invoked-event / misdeclaration / handler-panic)
    // but THREADS the real `caveat_binding` so the §7.3.8 post-input hook + the
    // durable cross-invocation counter CAS (`max_calls` / `amount_max_cumulative`
    // / `rate_window`) run for this open — matching what the same-context
    // production open does. `params.caveats` / `params.ucan_cid` bound only the
    // per-stream chunk ceiling; the value-caveat gate runs iff `caveat_binding`
    // is `Some` (supplied by the FFI caller / SCP-OUT-047).
    let mut handle = supervisor
        .open_outlet_stream(
            operating_context_id,
            registry,
            outlet_id,
            input,
            invoker_did,
            timeout_ms,
            executor,
            None,
            None,
            None,
            caveat_binding,
            params,
        )
        .await
        .map_err(|rejection| rejection.to_invocation_error())?;

    // Take B's plaintext operator-signed chunk receiver.
    let inner_rx = handle
        .receiver()
        .ok_or_else(|| InvocationError::ExecutionFailed {
            message: "cross-context bridge: B-side stream handle yielded no receiver".to_owned(),
        })?;

    // Bounded outer channel (=1) so forward-N precedes request-N+1 (AC3): the
    // bridge cannot pull chunk N+1 from `inner_rx` until chunk N has been
    // accepted by A's invoker. Each item is a `ForwardedStreamFrame` carrying the
    // per-sender `base_sequence` anchor (SCP-OUT-044) alongside the unmodified
    // operator-signed chunk.
    let (outer_tx, outer_rx) = mpsc::channel::<ForwardedStreamFrame>(1);

    // Committer-assigned leaf timestamp for A's close event (a local wall-clock
    // reading is correct — A's close event is authored once by the bridge, not
    // a cross-member convergent commit leaf).
    let timestamp_secs = supervisor.clock_ref().map_or(0, |clock| {
        use scp_clock::Clock as _;
        clock.now_secs()
    });

    // Spawn the OFF-MAILBOX bridge task owning the inner receiver, the outer
    // sender, the PINNED descriptor, the schemas, and A's event-log provider.
    tokio::spawn(run_cross_context_bridge(
        inner_rx,
        outer_tx,
        descriptor,
        output_schema,
        aggregate_schema,
        a_event_log,
        receiving_context_id.to_owned(),
        invoker_did.clone(),
        request_id,
        outlet_id.clone(),
        input_hash,
        governing_chain_depth,
        timestamp_secs,
        MAX_CROSS_CONTEXT_STREAM_CHUNKS,
        None,
    ));

    Ok(outer_rx)
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
        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            input,
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
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

        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
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

        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
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

        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"nonexistent-outlet".to_owned(),
            serde_json::json!({}),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
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
        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!("not an object"),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
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

        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            Some(50), // 50ms timeout -- will expire before the 5s sleep.
            slow_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
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

        let result = invoke_outlet_with_cancellation_aggregating(
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

        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            failing_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
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

        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            bad_output_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
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

        let (output, event, _consequences, _receipt) = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            input.clone(),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
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

        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
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
        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            Some(999_999), // Above MAX_TIMEOUT_MS
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
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
        let denied = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
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
        let allowed = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
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
        let denied = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
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
        let allowed = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
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

        let result = super::invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &invoker,
            None,
            add_executor,
            Some(&mut economy),
            None,
        )
        .await;
        assert!(
            matches!(result, Err(super::InvocationError::BudgetExceeded { .. })),
            "should return BudgetExceeded when budget is insufficient, got: {result:?}"
        );
    }

    // =======================================================================
    // Streaming entry point (SCP-OUT-033 / §5.4.5): the executor-based
    // `invoke_outlet<E>` machinery ported in chunk 2a.
    // =======================================================================

    /// Drains a `mpsc::Receiver<OutletStreamChunk>` into a `Vec` until
    /// EOS, asserting that sequence numbers are strictly monotonic
    /// starting at `0` (PRD AC4).
    async fn drain_stream_with_sequence_invariant(
        mut rx: tokio::sync::mpsc::Receiver<OutletStreamChunk>,
    ) -> Vec<OutletStreamChunk> {
        let mut chunks = Vec::new();
        let mut expected_seq: u64 = 0;
        while let Some(chunk) = rx.recv().await {
            assert_eq!(
                chunk.sequence, expected_seq,
                "sequence must be strictly monotonic per request_id (PRD AC4)"
            );
            expected_seq = expected_seq.saturating_add(1);
            chunks.push(chunk);
        }
        chunks
    }

    /// A [`HandlerPanicSink`] that forwards each event over an unbounded
    /// channel — a Mutex-free capture surface for tests (the reference's
    /// `InMemoryHandlerPanicSink` is intentionally not on this branch; it
    /// backs its Vec with `std::sync::Mutex`, banned in scp-runtime).
    struct ChannelPanicSink {
        tx: tokio::sync::mpsc::UnboundedSender<scp_protocol::context::outlets::OutletVerifiedEvent>,
    }

    impl super::HandlerPanicSink for ChannelPanicSink {
        fn record(&self, event: scp_protocol::context::outlets::OutletVerifiedEvent) {
            let _ = self.tx.send(event);
        }
    }

    /// AC8 — a single-value executor produces a two-chunk stream ending in
    /// `End`. The default `OutletExecutor::exec_action_stream` impl
    /// delegates to `exec_action`, pushes the returned `Value` as one
    /// `Data` chunk, and the framework appends `End`.
    #[tokio::test]
    async fn invoke_outlet_single_value_executor_produces_two_chunk_stream_ending_in_end() {
        struct AddExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for AddExecutor {
            async fn exec_action(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                input: serde_json::Value,
            ) -> Result<serde_json::Value, super::OutletExecutorError> {
                let a = input["a"].as_f64().unwrap_or(0.0);
                let b = input["b"].as_f64().unwrap_or(0.0);
                Ok(serde_json::json!({ "result": a + b }))
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: std::sync::Arc<dyn super::OutletExecutor> = std::sync::Arc::new(AddExecutor);

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 3, "b": 4}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            None,
            None,
            [0u8; 32],
        )
        .await
        .expect("invoke_outlet should accept a well-formed open");

        let chunks = drain_stream_with_sequence_invariant(rx).await;

        assert_eq!(
            chunks.len(),
            2,
            "single-value executor must produce exactly 2 chunks (Data + End); got {chunks:?}"
        );
        match &chunks[0].payload {
            ChunkPayload::Data { value } => {
                assert_eq!(*value, serde_json::json!({"result": 7.0}));
            }
            other => panic!("expected first chunk = Data, got {other:?}"),
        }
        assert!(
            matches!(chunks[1].payload, ChunkPayload::End { .. }),
            "expected second chunk = End, got {:?}",
            chunks[1].payload
        );
        // PRD AC4: both chunks share the same request_id.
        assert_eq!(chunks[0].request_id, chunks[1].request_id);
    }

    /// AC9 — a streaming executor produces multiple `Data` chunks followed
    /// by a single terminal `End`. The executor overrides
    /// `exec_action_stream` directly and writes three `Data` chunks into
    /// the framework-provided `tx` before returning.
    #[tokio::test]
    async fn invoke_outlet_streaming_executor_produces_data_chunks_then_end() {
        struct StreamingExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for StreamingExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                for i in 0..3u32 {
                    let _ = tx
                        .send(ChunkPayload::Data {
                            value: serde_json::json!({ "tick": i }),
                        })
                        .await;
                }
                Ok(())
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: std::sync::Arc<dyn super::OutletExecutor> =
            std::sync::Arc::new(StreamingExecutor);

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            None,
            None,
            [0u8; 32],
        )
        .await
        .expect("invoke_outlet should accept a well-formed open");

        let chunks = drain_stream_with_sequence_invariant(rx).await;

        assert_eq!(
            chunks.len(),
            4,
            "streaming executor must produce 3 Data + 1 End = 4 chunks; got {chunks:?}"
        );
        for (i, chunk) in chunks.iter().enumerate().take(3) {
            match &chunk.payload {
                ChunkPayload::Data { value } => {
                    let expected = u32::try_from(i).expect("3 chunks fit in u32");
                    assert_eq!(value["tick"], serde_json::json!(expected));
                }
                other => panic!("chunk[{i}] expected Data, got {other:?}"),
            }
        }
        assert!(
            matches!(chunks[3].payload, ChunkPayload::End { .. }),
            "chunk[3] must be End, got {:?}",
            chunks[3].payload
        );
    }

    /// AC10 — a panicking executor produces a single terminal `Error` chunk
    /// with code `SCP-OUTLET-6130` (`CODE_EXECUTION_FAULT`), `terminal: true`,
    /// and emits the §5.4.2 `OutletVerified` `HandlerPanicked` signal through
    /// the panic sink.
    #[tokio::test]
    async fn invoke_outlet_panicking_executor_produces_terminal_error_chunk() {
        struct PanickingExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for PanickingExecutor {
            async fn exec_action(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
            ) -> Result<serde_json::Value, super::OutletExecutorError> {
                panic!("operator-side defect");
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: std::sync::Arc<dyn super::OutletExecutor> =
            std::sync::Arc::new(PanickingExecutor);
        let (tx, mut sink_rx) = tokio::sync::mpsc::unbounded_channel();
        let panic_sink_dyn: std::sync::Arc<dyn super::HandlerPanicSink> =
            std::sync::Arc::new(ChannelPanicSink { tx });

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            Some(panic_sink_dyn),
            None,
            None,
            [0u8; 32],
        )
        .await
        .expect("synchronous validation must pass before the panic fires");

        let chunks = drain_stream_with_sequence_invariant(rx).await;

        assert_eq!(
            chunks.len(),
            1,
            "panicking executor produces exactly one terminal Error chunk; got {chunks:?}"
        );
        match &chunks[0].payload {
            ChunkPayload::Error {
                code,
                terminal,
                message,
            } => {
                assert_eq!(
                    code, CODE_EXECUTION_FAULT,
                    "code must be SCP-OUTLET-6130 (CODE_EXECUTION_FAULT)"
                );
                assert!(*terminal, "terminal must be true (PRD AC6)");
                assert!(
                    message.contains("operator-side defect"),
                    "panic payload must surface in the chunk message; got {message}"
                );
            }
            other => panic!("expected terminal Error chunk, got {other:?}"),
        }

        // SCP-OUT-028 parallel-signal observability: exactly one
        // HandlerPanicked OutletVerified event emitted.
        let mut events = Vec::new();
        while let Ok(ev) = sink_rx.try_recv() {
            events.push(ev);
        }
        assert_eq!(
            events.len(),
            1,
            "exactly one HandlerPanicked OutletVerified event emitted"
        );
        assert!(!events[0].integrity_ok);
        assert_eq!(
            events[0].reason,
            Some(scp_protocol::context::outlets::OutletVerifiedReason::HandlerPanicked)
        );
    }

    /// An [`OutletInvokedEventSink`] that forwards each recorded event over an
    /// unbounded channel — a Mutex-free capture surface (Mutex is banned in
    /// scp-runtime; the reference in-memory sinks live on other crates).
    struct ChannelInvokedSink {
        tx: tokio::sync::mpsc::UnboundedSender<OutletInvokedEvent>,
    }

    impl super::OutletInvokedEventSink for ChannelInvokedSink {
        fn record(&self, event: OutletInvokedEvent) {
            let _ = self.tx.send(event);
        }
    }

    /// Drains every event a [`ChannelInvokedSink`] captured (call after the
    /// stream has fully closed and the spawned task has dropped its sink).
    fn drain_invoked_events(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<OutletInvokedEvent>,
    ) -> Vec<OutletInvokedEvent> {
        let mut events = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }
        events
    }

    /// **033 AC10 / 034 AC7** — a streaming executor that outlives the timeout
    /// is force-closed by the framework with a terminal `Error` chunk carrying
    /// `code == SCP-OUTLET-6130` (`CODE_EXECUTION_FAULT`) and `terminal: true`.
    ///
    /// The framework routes the timeout under the `execution.timeout`
    /// (`SLUG_EXECUTION_TIMEOUT`) slug — emitted on the `tracing` diagnostic;
    /// the chunk message itself is the human-readable "timed out after {N}ms"
    /// form (see [`build_terminal_chunk`]).
    #[tokio::test]
    async fn invoke_outlet_streaming_timeout_emits_terminal_fault_033_ac10_034_ac7() {
        struct SlowStreamingExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for SlowStreamingExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                // Emit one Data chunk, then sleep well past the timeout so the
                // framework's deadline fires before a terminal is returned.
                let _ = tx
                    .send(ChunkPayload::Data {
                        value: serde_json::json!({ "tick": 0 }),
                    })
                    .await;
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(())
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: std::sync::Arc<dyn super::OutletExecutor> =
            std::sync::Arc::new(SlowStreamingExecutor);

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            Some(50), // 50ms timeout — fires before the 5s sleep.
            executor,
            None,
            None,
            None,
            None,
            [0u8; 32],
        )
        .await
        .expect("invoke_outlet should accept a well-formed open");

        let chunks = drain_stream_with_sequence_invariant(rx).await;
        let terminal = chunks
            .last()
            .expect("stream must emit at least the terminal chunk");
        match &terminal.payload {
            ChunkPayload::Error {
                code,
                message,
                terminal: is_terminal,
            } => {
                assert_eq!(
                    code, CODE_EXECUTION_FAULT,
                    "streaming timeout maps to SCP-OUTLET-6130 (CODE_EXECUTION_FAULT)"
                );
                assert!(*is_terminal, "timeout terminal chunk must be terminal");
                assert!(
                    message.contains("timed out"),
                    "timeout terminal message describes the deadline, got: {message}"
                );
            }
            other => panic!("expected terminal Error chunk on timeout, got {other:?}"),
        }
    }

    /// **035 AC2** — a 5-chunk stream (4 `Data` + framework `End`) emits
    /// EXACTLY ONE `OutletInvokedEvent` with `stream_chunk_count == 5`.
    #[tokio::test]
    async fn invoke_outlet_emits_single_event_with_chunk_count_035_ac2() {
        struct FourDataExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for FourDataExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                for i in 0..4u32 {
                    let _ = tx
                        .send(ChunkPayload::Data {
                            value: serde_json::json!({ "tick": i }),
                        })
                        .await;
                }
                Ok(())
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: std::sync::Arc<dyn super::OutletExecutor> =
            std::sync::Arc::new(FourDataExecutor);
        let (tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
        let sink: std::sync::Arc<dyn super::OutletInvokedEventSink> =
            std::sync::Arc::new(ChannelInvokedSink { tx });

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            Some(sink),
            None,
            [0u8; 32],
        )
        .await
        .expect("invoke_outlet should accept a well-formed open");

        let chunks = drain_stream_with_sequence_invariant(rx).await;
        assert_eq!(chunks.len(), 5, "4 Data + 1 terminal End = 5 chunks");
        let events = drain_invoked_events(&mut event_rx);
        assert_eq!(events.len(), 1, "exactly ONE OutletInvokedEvent per stream");
        assert_eq!(
            events[0].stream_chunk_count, 5,
            "event stream_chunk_count counts all 5 chunks including the terminal End"
        );
        assert_eq!(
            events[0].stream_terminal_status,
            StreamTerminalStatus::Ok,
            "a clean End close records the Ok terminal status"
        );
    }

    /// **035 AC5** — a non-streaming (one-shot) invocation emits ONE event
    /// with `stream_chunk_count == 2` (Data + End). §5.4.5:607: "A
    /// non-streaming invocation is a stream that emits exactly two chunks:
    /// Data(output) followed by End(output) ... the wire contract is always
    /// the streaming form." A one-shot executor overrides only the
    /// non-streaming `exec_action`; the default `exec_action_stream` routes
    /// its single value through `one_shot_to_stream` (one `Data` chunk) and
    /// the framework appends the terminal `End`, yielding exactly two chunks.
    #[tokio::test]
    async fn invoke_outlet_one_shot_emits_two_chunk_event_035_ac5() {
        struct OneShotExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for OneShotExecutor {
            // Non-streaming: returns a single value. The default
            // `exec_action_stream` adapter turns it into a Data chunk; the
            // framework appends the terminal End.
            async fn exec_action(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
            ) -> Result<serde_json::Value, super::OutletExecutorError> {
                Ok(serde_json::json!({ "sum": 3 }))
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: std::sync::Arc<dyn super::OutletExecutor> =
            std::sync::Arc::new(OneShotExecutor);
        let (tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
        let sink: std::sync::Arc<dyn super::OutletInvokedEventSink> =
            std::sync::Arc::new(ChannelInvokedSink { tx });

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            Some(sink),
            None,
            [0u8; 32],
        )
        .await
        .expect("invoke_outlet should accept a well-formed open");

        let chunks = drain_stream_with_sequence_invariant(rx).await;
        assert_eq!(
            chunks.len(),
            2,
            "one-shot invocation is a two-chunk stream: Data(output) + End"
        );
        let events = drain_invoked_events(&mut event_rx);
        assert_eq!(events.len(), 1, "exactly ONE OutletInvokedEvent per stream");
        assert_eq!(
            events[0].stream_chunk_count, 2,
            "035 AC5: one-shot invocation emits an event with stream_chunk_count == 2"
        );
        assert_eq!(
            events[0].stream_terminal_status,
            StreamTerminalStatus::Ok,
            "clean End close on the one-shot path records Ok"
        );
    }

    /// **035 AC4** — a failed stream (executor returns `Err`, framework emits a
    /// terminal `Error`) emits ONE event with
    /// `stream_terminal_status == Error(code)`.
    #[tokio::test]
    async fn invoke_outlet_failed_stream_records_error_terminal_status_035_ac4() {
        struct FailingExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for FailingExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                // One Data chunk, then fail — the framework appends a terminal
                // Error chunk on the Err return.
                let _ = tx
                    .send(ChunkPayload::Data {
                        value: serde_json::json!({ "tick": 0 }),
                    })
                    .await;
                Err(super::OutletExecutorError::Failed(
                    "operator-side failure".to_owned(),
                ))
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: std::sync::Arc<dyn super::OutletExecutor> =
            std::sync::Arc::new(FailingExecutor);
        let (tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
        let sink: std::sync::Arc<dyn super::OutletInvokedEventSink> =
            std::sync::Arc::new(ChannelInvokedSink { tx });

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            Some(sink),
            None,
            [0u8; 32],
        )
        .await
        .expect("invoke_outlet should accept a well-formed open");

        let chunks = drain_stream_with_sequence_invariant(rx).await;
        assert!(
            matches!(
                chunks.last().map(|c| &c.payload),
                Some(ChunkPayload::Error { terminal: true, .. })
            ),
            "failed stream ends in a terminal Error chunk"
        );
        let events = drain_invoked_events(&mut event_rx);
        assert_eq!(events.len(), 1, "exactly ONE OutletInvokedEvent per stream");
        match &events[0].stream_terminal_status {
            StreamTerminalStatus::Error(code) => assert_eq!(
                code, CODE_EXECUTION_FAULT,
                "failed-stream terminal status carries the executor-fault code"
            ),
            other => panic!("expected Error terminal status, got {other:?}"),
        }
    }

    /// **035 AC6** — event-log replay reconstructs `stream_manifest_hash`
    /// identically: the manifest root recorded on the emitted event equals an
    /// INDEPENDENT recomputation of `compute_chunk_manifest_root` over the very
    /// chunk sequence the receiver observed.
    #[tokio::test]
    async fn invoke_outlet_manifest_hash_reconstructs_on_replay_035_ac6() {
        struct ThreeDataExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for ThreeDataExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                for i in 0..3u32 {
                    let _ = tx
                        .send(ChunkPayload::Data {
                            value: serde_json::json!({ "tick": i }),
                        })
                        .await;
                }
                Ok(())
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: std::sync::Arc<dyn super::OutletExecutor> =
            std::sync::Arc::new(ThreeDataExecutor);
        let (tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
        let sink: std::sync::Arc<dyn super::OutletInvokedEventSink> =
            std::sync::Arc::new(ChannelInvokedSink { tx });

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            Some(sink),
            None,
            [0u8; 32],
        )
        .await
        .expect("invoke_outlet should accept a well-formed open");

        // The exact ordered chunk sequence the receiver observed (3 Data +
        // terminal End), signed and sequence-numbered by the framework.
        let chunks = drain_stream_with_sequence_invariant(rx).await;
        assert_eq!(chunks.len(), 4, "3 Data + terminal End");

        let events = drain_invoked_events(&mut event_rx);
        assert_eq!(events.len(), 1, "exactly ONE OutletInvokedEvent per stream");
        let recorded_root = events[0].stream_manifest_hash;

        // Independent replay reconstruction: recompute the RFC-6962 root over
        // the same sealed chunk sequence and assert byte-identity.
        let replayed_root =
            scp_protocol::context::outlets::stream::compute_chunk_manifest_root(&chunks)
                .expect("manifest root recomputation");
        assert_eq!(
            recorded_root, replayed_root,
            "recorded stream_manifest_hash must reconstruct identically on replay"
        );
        assert_ne!(
            recorded_root, [0u8; 32],
            "a non-empty stream commits a non-sentinel manifest root"
        );
    }

    // =====================================================================
    // SCP-OUT-036 — best-effort cross-context re-encrypting streaming bridge
    // =====================================================================
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    mod cross_context_036 {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        use ed25519_dalek::{Signer as _, SigningKey};

        use super::*;
        use crate::context::builder::ContextEventLogProvider;
        use crate::context::outlets::signer::InProcessStreamSigner;
        use crate::context::providers::event_log::MerkleEventLogProvider;
        use crate::context::state::context_id_to_bytes;
        use scp_protocol::context::outlets::stream::{
            OutletStreamOpen, compute_chunk_sig_preimage,
        };

        const B_CTX: &str = "ctx-b-036";
        const A_CTX: &str = "ctx-a-036";
        const OUTLET: &str = "calculator";
        const CB: [u8; 32] = [0x11; 32];
        const RID: RequestId = [0xAB; 16];
        const INVOKER: &str = "did:dht:z6MkXctxInvoker036";

        /// The operator's deterministic Ed25519 signing key (B-side operator).
        fn operator_key() -> SigningKey {
            SigningKey::from_bytes(&[0x5c; 32])
        }

        /// Signs one chunk under the §5.4.5 `SCP-OUTLET-CHUNK-SIG-V1:` preimage
        /// with the given operator key and pinned `(context_id, outlet_id,
        /// caveats_binding)` — the exact operator-authored shape B produces.
        fn sign_chunk(
            operator: &SigningKey,
            context_id: &str,
            outlet_id: &str,
            caveats_binding: &[u8; 32],
            sequence: u64,
            payload: ChunkPayload,
        ) -> OutletStreamChunk {
            let preimage = compute_chunk_sig_preimage(
                context_id,
                outlet_id,
                &RID,
                sequence,
                caveats_binding,
                &payload,
            )
            .expect("chunk preimage");
            let sig = operator.sign(&preimage).to_bytes();
            OutletStreamChunk {
                request_id: RID,
                sequence,
                payload,
                sig,
            }
        }

        /// The pinned verification descriptor for B's operator over `B_CTX`.
        fn pinned_descriptor(operator: &SigningKey) -> CrossContextVerificationDescriptor {
            CrossContextVerificationDescriptor {
                operator_pk: operator.verifying_key(),
                operating_context_id: B_CTX.to_owned(),
                outlet_id: OUTLET.to_owned(),
                caveats_binding: CB,
                expected_request_id: RID,
            }
        }

        /// The empty JSON Schema — accepts ANY instance (object, array, scalar,
        /// null). Used where the test is not exercising a schema violation, so
        /// the operator's default `End.aggregate` (whatever its shape) passes.
        fn permissive_schema() -> serde_json::Value {
            serde_json::json!({})
        }

        /// An output schema that REQUIRES a numeric `result` and forbids extra
        /// keys — a value lacking a numeric `result` violates it.
        fn strict_output_schema() -> serde_json::Value {
            serde_json::json!({
                "type": "object",
                "properties": { "result": { "type": "number" } },
                "required": ["result"],
                "additionalProperties": false
            })
        }

        /// An aggregate schema that REQUIRES a string `summary` and forbids
        /// extra keys — disjoint from [`strict_output_schema`].
        fn aggregate_schema() -> serde_json::Value {
            serde_json::json!({
                "type": "object",
                "properties": { "summary": { "type": "string" } },
                "required": ["summary"],
                "additionalProperties": false
            })
        }

        fn end_payload(aggregate: serde_json::Value) -> ChunkPayload {
            ChunkPayload::End {
                aggregate,
                provenance: scp_protocol::provenance::DataProvenance {
                    source_context: B_CTX.to_owned(),
                    source_type: scp_protocol::provenance::SourceType::Persistent,
                    counterparties: Vec::new(),
                    purpose: None,
                    discovery_method: scp_protocol::provenance::DiscoveryMethod::OutOfBand,
                    age: std::time::Duration::from_secs(0),
                    memory_scope: scp_protocol::context::params::MemoryScope::Full,
                    chain_depth: 0,
                    chain_path: None,
                    payment_amount: None,
                    payment_adapter: None,
                    payment_receipt_id: None,
                },
                execution_time_ms: 5,
            }
        }

        /// Initializes a fresh receiving-context (A) event log.
        async fn fresh_a_log() -> (Arc<MerkleEventLogProvider>, [u8; 32]) {
            let provider = Arc::new(MerkleEventLogProvider::new());
            let a_bytes = context_id_to_bytes(A_CTX);
            provider.init_event_log(&a_bytes).await.expect("init A log");
            (provider, a_bytes)
        }

        /// Reads back A's recorded `OutletInvokedEvent`, if any.
        fn read_a_invoked(
            a_log: &MerkleEventLogProvider,
            a_bytes: &[u8; 32],
        ) -> Option<OutletInvokedEvent> {
            a_log.entries(a_bytes)?.into_iter().find_map(|entry| {
                if entry.event_type == scp_event_log::EventType::OutletInvoked {
                    serde_json::from_slice::<OutletInvokedEvent>(&entry.payload.data).ok()
                } else {
                    None
                }
            })
        }

        /// Drives the bridge core to completion over a pre-built chunk
        /// sequence, returning what A's invoker received plus A's log handle.
        async fn drive_bridge(
            chunks: Vec<OutletStreamChunk>,
            descriptor: CrossContextVerificationDescriptor,
            output_schema: serde_json::Value,
            aggregate_schema: Option<serde_json::Value>,
            fault_probe: Option<BridgeFaultProbe>,
        ) -> (
            Vec<OutletStreamChunk>,
            Arc<MerkleEventLogProvider>,
            [u8; 32],
        ) {
            let (a_log, a_bytes) = fresh_a_log().await;
            let (inner_tx, inner_rx) = mpsc::channel::<OutletStreamChunk>(1);
            let (outer_tx, mut outer_rx) = mpsc::channel::<ForwardedStreamFrame>(1);
            let a_dyn: Arc<dyn ContextEventLogProvider> = a_log.clone();
            let bridge = tokio::spawn(run_cross_context_bridge(
                inner_rx,
                outer_tx,
                descriptor,
                output_schema,
                aggregate_schema,
                a_dyn,
                A_CTX.to_owned(),
                DID::from(INVOKER),
                RID,
                OUTLET.to_owned(),
                "input-hash".to_owned(),
                3,
                0,
                MAX_CROSS_CONTEXT_STREAM_CHUNKS,
                fault_probe,
            ));
            let producer = tokio::spawn(async move {
                for chunk in chunks {
                    if inner_tx.send(chunk).await.is_err() {
                        break;
                    }
                }
            });
            // Unwrap the runtime `ForwardedStreamFrame` back to the bare chunk so
            // this helper's contract ("what A's invoker received") stays a
            // `Vec<OutletStreamChunk>` — the `base_sequence` anchor is asserted
            // directly by the SCP-OUT-044 unit tests, not here.
            let mut received = Vec::new();
            while let Some(frame) = outer_rx.recv().await {
                received.push(frame.chunk);
            }
            producer.await.expect("producer task");
            bridge.await.expect("bridge task");
            (received, a_log, a_bytes)
        }

        fn assert_terminal_error(chunk: &OutletStreamChunk, expected_code: &str) {
            match &chunk.payload {
                ChunkPayload::Error { code, terminal, .. } => {
                    assert_eq!(code, expected_code, "terminal error code");
                    assert!(*terminal, "must be terminal");
                }
                other => panic!("expected terminal Error, got {other:?}"),
            }
        }

        // ---- AC2: Ok variant is a plaintext mpsc::Receiver<OutletStreamChunk>.

        struct NoopExecutor;
        #[async_trait::async_trait]
        impl super::super::OutletExecutor for NoopExecutor {
            async fn exec_action(
                &self,
                _ctx: &mut super::super::MutableInvocation<'_>,
                _input: serde_json::Value,
            ) -> Result<serde_json::Value, super::super::OutletExecutorError> {
                Ok(serde_json::json!({}))
            }
        }

        /// Compile-level proof that `invoke_outlet_cross_context`'s Ok variant
        /// is exactly `mpsc::Receiver<ForwardedStreamFrame>` — a PLAINTEXT chunk
        /// (`frame.chunk`) paired with the per-sender `base_sequence` anchor
        /// (SCP-OUT-044), NOT a sealed/ciphertext type. Never executed — the
        /// explicit type annotation on the awaited result fails to compile if
        /// the return type drifts.
        #[allow(dead_code)]
        async fn ac2_return_type_is_plaintext_receiver(
            supervisor: &Arc<crate::context::supervisor::Supervisor>,
            a_event_log: Arc<dyn crate::context::builder::ContextEventLogProvider>,
            registry: &OutletRegistry,
            outlet_id: &OutletId,
            invoker_did: &DID,
            incoming_open: &OutletStreamOpen,
            params: crate::context::outlets::dispatch::OpenStreamParams,
        ) {
            let out: Result<mpsc::Receiver<ForwardedStreamFrame>, InvocationError> =
                invoke_outlet_cross_context::<NoopExecutor>(
                    supervisor,
                    a_event_log,
                    "a",
                    "b",
                    registry,
                    outlet_id,
                    serde_json::json!({}),
                    invoker_did,
                    None,
                    Arc::new(NoopExecutor),
                    incoming_open,
                    None,
                    params,
                )
                .await;
            drop(out);
        }

        #[tokio::test]
        async fn ac2_ok_variant_is_plaintext_receiver() {
            // Runtime: a chunk read off the bridge's outer receiver (the exact
            // value `invoke_outlet_cross_context` returns) exposes a PLAINTEXT
            // `ChunkPayload` — never a sealed blob.
            let op = operator_key();
            let chunks = vec![
                sign_chunk(
                    &op,
                    B_CTX,
                    OUTLET,
                    &CB,
                    0,
                    ChunkPayload::Data {
                        value: serde_json::json!({ "result": 1 }),
                    },
                ),
                sign_chunk(
                    &op,
                    B_CTX,
                    OUTLET,
                    &CB,
                    1,
                    end_payload(serde_json::json!({ "result": 1 })),
                ),
            ];
            let (received, _a_log, _a_bytes) = drive_bridge(
                chunks,
                pinned_descriptor(&op),
                permissive_schema(),
                None,
                None,
            )
            .await;
            assert!(
                matches!(received[0].payload, ChunkPayload::Data { .. }),
                "first forwarded chunk is a plaintext Data payload"
            );
        }

        // ---- AC3: no buffering — chunk N delivered before N+1 requested.

        #[tokio::test]
        async fn ac3_bridge_forwards_without_buffering() {
            let op = operator_key();
            let (a_log, _a_bytes) = fresh_a_log().await;
            let a_dyn: Arc<dyn ContextEventLogProvider> = a_log.clone();
            let (inner_tx, inner_rx) = mpsc::channel::<OutletStreamChunk>(1);
            let (outer_tx, mut outer_rx) = mpsc::channel::<ForwardedStreamFrame>(1);

            let bridge = tokio::spawn(run_cross_context_bridge(
                inner_rx,
                outer_tx,
                pinned_descriptor(&op),
                permissive_schema(),
                None,
                a_dyn,
                A_CTX.to_owned(),
                DID::from(INVOKER),
                RID,
                OUTLET.to_owned(),
                "input-hash".to_owned(),
                3,
                0,
                MAX_CROSS_CONTEXT_STREAM_CHUNKS,
                None,
            ));

            // The highest sequence the source has SUCCESSFULLY handed to the
            // inner channel. Because the outer channel is bounded to 1 and the
            // bridge holds at most one chunk in flight, the source can never get
            // more than 2 chunks ahead of an unconsumed receiver — proving the
            // bridge does NOT drain the whole stream into an internal buffer.
            let accepted = Arc::new(AtomicU64::new(0));
            let producer = {
                let accepted = Arc::clone(&accepted);
                let op = op.clone();
                tokio::spawn(async move {
                    for seq in 0..6u64 {
                        let payload = ChunkPayload::Data {
                            value: serde_json::json!({ "result": seq }),
                        };
                        let chunk = sign_chunk(&op, B_CTX, OUTLET, &CB, seq, payload);
                        if inner_tx.send(chunk).await.is_err() {
                            break;
                        }
                        accepted.fetch_add(1, Ordering::SeqCst);
                    }
                })
            };

            // Let the pipeline reach steady state WITHOUT consuming `outer_rx`.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let ahead = accepted.load(Ordering::SeqCst);
            // Steady-state cap = inner(1) + one chunk held in the bridge (blocked
            // forwarding into the full outer channel) + outer(1) = 3. A bridge
            // that accumulated the whole stream into a Vec would let all 6
            // through. `<= 3` with 6 fed proves it forwards-as-produced.
            assert!(
                ahead <= 3,
                "backpressure caps the source at 3 chunks ahead of an unconsumed receiver; \
                 got {ahead} of 6 — the bridge is buffering the stream"
            );

            // Now drain and assert strict in-order delivery with no gaps. Unwrap
            // each `ForwardedStreamFrame` to its chunk; the `base_sequence`
            // anchor is asserted by the SCP-OUT-044 unit tests.
            let mut received = Vec::new();
            while let Some(frame) = outer_rx.recv().await {
                received.push(frame.chunk);
            }
            producer.await.expect("producer");
            bridge.await.expect("bridge");
            // The six Data chunks are forwarded in order; because the producer
            // drops its sender WITHOUT emitting a terminal, the bridge now
            // synthesizes a terminal transport-fault (§5.4.5 terminal guarantee)
            // as the final chunk — so A never truncates after a non-terminal
            // Data.
            assert_eq!(
                received.len(),
                7,
                "six Data chunks + one synthesized terminal transport-fault"
            );
            for (i, chunk) in received.iter().take(6).enumerate() {
                assert_eq!(chunk.sequence, i as u64, "Data delivered strictly in order");
                assert!(
                    matches!(chunk.payload, ChunkPayload::Data { .. }),
                    "the first six forwarded chunks are Data payloads"
                );
            }
            assert_terminal_error(received.last().unwrap(), CODE_TRANSPORT_FAULT);
        }

        // ---- AC4: A-leg open inherits chain_depth; chunks never carry it.

        #[test]
        fn ac4_a_leg_open_inherits_chain_depth_verbatim() {
            let incoming = OutletStreamOpen {
                request_id: RID,
                outlet_id: OUTLET.to_owned(),
                input: serde_json::json!({ "a": 1 }),
                invoker_did: DID::from(INVOKER),
                ucan: vec![0x01, 0x02],
                caveats_binding: CB,
                chain_depth: 3,
                credit_window: 8,
                estimated_chunk_count: 5,
                session_id: None,
                timeout_ms: 1000,
            };
            let a_leg = build_onward_a_leg_open(&incoming);
            assert_eq!(
                a_leg.chain_depth, 3,
                "the onward A-leg open inherits chain_depth == 3 verbatim (no +1)"
            );
            // A forwarded chunk cannot mutate chain_depth: it is structurally
            // absent from OutletStreamChunk (only request_id/sequence/payload/
            // sig). This constructs a chunk and confirms the field set.
            let chunk = sign_chunk(
                &operator_key(),
                B_CTX,
                OUTLET,
                &CB,
                0,
                ChunkPayload::Data {
                    value: serde_json::json!({ "result": 1 }),
                },
            );
            // Exhaustive destructure — a future `chain_depth` field would break
            // this compile, enforcing "chunks do not carry chain_depth".
            let OutletStreamChunk {
                request_id: _,
                sequence: _,
                payload: _,
                sig: _,
            } = chunk;
        }

        // ---- AC5: Data violating output_schema → terminal 6140.

        #[tokio::test]
        async fn ac5_data_schema_violation_emits_output_terminal() {
            let op = operator_key();
            let chunks = vec![
                sign_chunk(
                    &op,
                    B_CTX,
                    OUTLET,
                    &CB,
                    0,
                    ChunkPayload::Data {
                        value: serde_json::json!({ "result": 1 }),
                    },
                ),
                // Violates strict_output_schema (`result` must be a number).
                sign_chunk(
                    &op,
                    B_CTX,
                    OUTLET,
                    &CB,
                    1,
                    ChunkPayload::Data {
                        value: serde_json::json!({ "result": "not-a-number" }),
                    },
                ),
            ];
            let (received, _a_log, _a_bytes) = drive_bridge(
                chunks,
                pinned_descriptor(&op),
                strict_output_schema(),
                None,
                None,
            )
            .await;
            // The valid Data prefix forwarded, then the terminal replaces the
            // offending chunk (ordering preserved).
            assert!(matches!(received[0].payload, ChunkPayload::Data { .. }));
            assert_terminal_error(received.last().unwrap(), CODE_OUTPUT_VIOLATION);
        }

        // ---- AC6: End.aggregate validated against aggregate_schema when set.

        #[tokio::test]
        async fn ac6_end_aggregate_uses_aggregate_schema_when_present() {
            let op = operator_key();
            // The aggregate satisfies aggregate_schema but VIOLATES
            // output_schema (no numeric `result`) — accepted because
            // aggregate_schema is present.
            let chunks = vec![sign_chunk(
                &op,
                B_CTX,
                OUTLET,
                &CB,
                0,
                end_payload(serde_json::json!({ "summary": "done" })),
            )];
            let (received, _a_log, _a_bytes) = drive_bridge(
                chunks,
                pinned_descriptor(&op),
                strict_output_schema(),
                Some(aggregate_schema()),
                None,
            )
            .await;
            assert_eq!(received.len(), 1, "the End is forwarded, not rejected");
            assert!(
                matches!(received[0].payload, ChunkPayload::End { .. }),
                "End satisfying aggregate_schema is accepted"
            );
        }

        // ---- AC7 accept: A's recorded manifest == B's recorded manifest.

        #[tokio::test]
        async fn ac7_accept_both_logs_same_manifest_hash() {
            // B produces the stream through its REAL same-context streaming path
            // (`invoke_outlet`), signing every chunk and recording its own
            // `OutletInvokedEvent` (B's log) via a capture sink.
            const DATA_CHUNKS: u32 = 9;
            struct NineDataExecutor;
            #[async_trait::async_trait]
            impl super::super::OutletExecutor for NineDataExecutor {
                async fn exec_action_stream(
                    &self,
                    _ctx: &mut super::super::MutableInvocation<'_>,
                    _input: serde_json::Value,
                    tx: tokio::sync::mpsc::Sender<ChunkPayload>,
                ) -> Result<(), super::super::OutletExecutorError> {
                    for i in 0..DATA_CHUNKS {
                        let _ = tx
                            .send(ChunkPayload::Data {
                                value: serde_json::json!({ "tick": i }),
                            })
                            .await;
                    }
                    Ok(())
                }
            }

            let op = operator_key();
            // B's signing context is the same-context handle id — pin the
            // descriptor to it so the bridge's verification accepts B's chunks.
            let context = active_context();
            let b_ctx_id = context.context_id().to_owned();
            let creator_did = "did:dht:z6MkCreator";
            let role_state = test_role_state(creator_did);
            let registry = setup_registry_with_outlet(&role_state, creator_did);
            let outlet_id_owned: OutletId = OUTLET.to_owned();
            let executor: Arc<dyn super::super::OutletExecutor> = Arc::new(NineDataExecutor);
            let signer: Arc<dyn crate::context::outlets::signer::StreamSigner> =
                Arc::new(InProcessStreamSigner::new(op.clone()));
            let (tx, mut b_events) = tokio::sync::mpsc::unbounded_channel();
            let b_sink: Arc<dyn super::super::OutletInvokedEventSink> =
                Arc::new(ChannelInvokedSink { tx });

            let b_rx = super::super::invoke_outlet(
                &context,
                &registry,
                &role_state,
                &outlet_id_owned,
                serde_json::json!({ "a": 1, "b": 2 }),
                &DID::from(creator_did),
                None,
                executor,
                None,
                None,
                Some(b_sink),
                Some(signer),
                CB,
            )
            .await
            .expect("B open");

            let b_chunks = drain_stream_with_sequence_invariant(b_rx).await;
            assert_eq!(b_chunks.len(), 10, "9 Data + terminal End");
            let b_event = {
                let mut ev = drain_invoked_events(&mut b_events);
                assert_eq!(ev.len(), 1, "exactly one B-side OutletInvoked");
                ev.remove(0)
            };
            let b_hash = b_event.stream_manifest_hash;

            // The bridge reassembles the SAME chunks and records A's log through
            // the verified-append boundary. Pin the descriptor to B's real
            // signing context.
            let descriptor = CrossContextVerificationDescriptor {
                operator_pk: op.verifying_key(),
                operating_context_id: b_ctx_id,
                outlet_id: OUTLET.to_owned(),
                caveats_binding: CB,
                // `invoke_outlet` mints its own fresh `request_id`; pin the
                // descriptor to the stream B actually produced (all chunks share
                // it) so the §5.4.5 crossing verification accepts B's chunks.
                expected_request_id: b_chunks[0].request_id,
            };
            let (received, a_log, a_bytes) = drive_bridge(
                b_chunks.clone(),
                descriptor,
                permissive_schema(),
                None,
                None,
            )
            .await;
            assert_eq!(received.len(), 10, "all 10 chunks forwarded to A");

            let a_event =
                read_a_invoked(&a_log, &a_bytes).expect("A must record its OutletInvoked at close");
            let a_hash = a_event.stream_manifest_hash;

            assert_eq!(
                received, b_chunks,
                "every forwarded chunk is byte-identical to B's (operator sig preserved, \
                 never re-signed, no synthesized terminal on the happy path)"
            );
            assert_eq!(
                a_hash, b_hash,
                "both event logs record the same 32-byte stream_manifest_hash"
            );
            assert_ne!(
                a_hash, [0u8; 32],
                "a 10-chunk stream commits a non-sentinel root"
            );
            assert_eq!(a_event.stream_chunk_count, 10);
            assert_eq!(a_event.chunks_billed, DATA_CHUNKS, "9 billable Data leaves");
            assert_eq!(a_event.chunks_billed, b_event.chunks_billed);
        }

        // ---- AC7 reject: a mismatched chunks_billed is wire-rejected.

        #[tokio::test]
        async fn ac7_reject_chunks_billed_mismatch_refused_at_append() {
            let (a_log, a_bytes) = fresh_a_log().await;
            let op = operator_key();
            let chunks = vec![
                sign_chunk(
                    &op,
                    A_CTX,
                    OUTLET,
                    &CB,
                    0,
                    ChunkPayload::Data {
                        value: serde_json::json!({ "result": 1 }),
                    },
                ),
                sign_chunk(
                    &op,
                    A_CTX,
                    OUTLET,
                    &CB,
                    1,
                    end_payload(serde_json::json!({ "result": 1 })),
                ),
            ];
            // A well-formed manifest over these chunks has chunks_billed == 1.
            // Record an event that LIES (chunks_billed == 5) and assert the
            // verified-append boundary refuses it (§5.4.5:566 wire-rejection).
            let manifest =
                scp_protocol::context::outlets::stream::compute_chunk_manifest_root(&chunks)
                    .unwrap();
            let mut terminal = StreamTerminalSummary::default();
            for c in &chunks {
                terminal.observe(&c.payload);
            }
            let bad_event = build_streaming_outlet_event(
                RID,
                &OUTLET.to_owned(),
                &DID::from(INVOKER),
                "input-hash".to_owned(),
                5,
                u32::try_from(chunks.len()).unwrap(),
                5, // WRONG: real billable count is 1.
                manifest,
                &terminal,
                None,
                None,
            );
            let err = a_log
                .append_outlet_invoked_verified(&a_bytes, &bad_event, &chunks, INVOKER, 0)
                .await
                .expect_err("mismatched chunks_billed must be refused at log-insert");
            assert!(
                err.to_string().contains("ChunksBilled")
                    || err.to_string().contains("chunks_billed"),
                "refusal must surface ChunksBilledMismatch, got: {err}"
            );
        }

        // ---- AC8: mid-stream bridge fault → terminal 6160.

        #[tokio::test]
        async fn ac8_mid_stream_bridge_failure_emits_transport_terminal() {
            let op = operator_key();
            let chunks = vec![
                sign_chunk(
                    &op,
                    B_CTX,
                    OUTLET,
                    &CB,
                    0,
                    ChunkPayload::Data {
                        value: serde_json::json!({ "result": 1 }),
                    },
                ),
                sign_chunk(
                    &op,
                    B_CTX,
                    OUTLET,
                    &CB,
                    1,
                    ChunkPayload::Data {
                        value: serde_json::json!({ "result": 2 }),
                    },
                ),
            ];
            // Force a bridge fault when processing sequence 1.
            let probe: BridgeFaultProbe = Box::new(|chunk: &OutletStreamChunk| {
                (chunk.sequence == 1).then(|| "injected re-encrypt fault".to_owned())
            });
            let (received, _a_log, _a_bytes) = drive_bridge(
                chunks,
                pinned_descriptor(&op),
                permissive_schema(),
                None,
                Some(probe),
            )
            .await;
            assert!(matches!(received[0].payload, ChunkPayload::Data { .. }));
            assert_terminal_error(received.last().unwrap(), CODE_TRANSPORT_FAULT);
        }

        // ---- AC9: End.aggregate violating aggregate_schema → terminal 6140.

        #[tokio::test]
        async fn ac9_end_aggregate_violation_emits_output_terminal() {
            let op = operator_key();
            // `summary` must be a string; a number violates aggregate_schema.
            let chunks = vec![sign_chunk(
                &op,
                B_CTX,
                OUTLET,
                &CB,
                0,
                end_payload(serde_json::json!({ "summary": 123 })),
            )];
            let (received, _a_log, _a_bytes) = drive_bridge(
                chunks,
                pinned_descriptor(&op),
                strict_output_schema(),
                Some(aggregate_schema()),
                None,
            )
            .await;
            assert_terminal_error(received.last().unwrap(), CODE_OUTPUT_VIOLATION);
        }

        // ---- AC10: seal-for-A over the existing MLS transport (see below).
        // (Implemented as a sibling sync test `ac10_seal_for_a_preserves_operator_sig`.)

        // ---- AC11: verify against the PINNED descriptor, never bridge input.

        #[tokio::test]
        async fn ac11_chunk_verified_against_pinned_descriptor_not_bridge_input() {
            let op = operator_key();
            // Direct helper check: a chunk signed under a DIFFERENT (bridge-
            // supplied) context_id fails verification against the pinned
            // descriptor (which pins B_CTX).
            let forged = sign_chunk(
                &op,
                "attacker-controlled-ctx",
                OUTLET,
                &CB,
                0,
                ChunkPayload::Data {
                    value: serde_json::json!({ "result": 1 }),
                },
            );
            assert!(
                !verify_forwarded_chunk(&pinned_descriptor(&op), &forged),
                "a chunk signed under a non-pinned context_id must NOT verify"
            );
            // A correctly-signed chunk verifies.
            let genuine = sign_chunk(
                &op,
                B_CTX,
                OUTLET,
                &CB,
                0,
                ChunkPayload::Data {
                    value: serde_json::json!({ "result": 1 }),
                },
            );
            assert!(verify_forwarded_chunk(&pinned_descriptor(&op), &genuine));

            // End-to-end: the bridge rejects the forged chunk with an
            // Authorization-class terminal rather than forwarding it.
            let (received, _a_log, _a_bytes) = drive_bridge(
                vec![forged],
                pinned_descriptor(&op),
                permissive_schema(),
                None,
                None,
            )
            .await;
            assert_terminal_error(received.last().unwrap(), CODE_AUTHORIZATION_DENIED);
        }

        // ---- AC12: zero-escrow economy gate.

        fn registration_with_cost(kind: OutletKind, amount: u64) -> OutletRegistration {
            OutletRegistration {
                outlet_id: OUTLET.to_owned(),
                kind,
                name: "Calc".to_owned(),
                description: "d".to_owned(),
                schema: OutletSchema {
                    input_schema: serde_json::json!({ "type": "object" }),
                    output_schema: serde_json::json!({ "type": "object" }),
                    aggregate_schema: None,
                },
                implementation_hash: [0u8; 32],
                test_vectors: vec![],
                operator_did: "did:dht:z6MkOperator".into(),
                cost: (amount > 0).then(|| scp_protocol::context::outlets::registry::OutletCost {
                    amount: scp_protocol::economy::types::Amount::new(amount),
                    currency: "USD".to_owned(),
                    payee: "did:dht:z6MkPayee".into(),
                    cost_formula: None,
                }),
                message_catalog: Vec::new(),
                registered_at: 0,
                signature: Vec::new(),
            }
        }

        #[test]
        fn ac12_paid_action_rejected_query_and_zero_cost_accepted() {
            use scp_protocol::economy::types::Amount;
            // Paid Action (cost.amount > 0) → rejected, no receiver ever built.
            // (`cost_per_chunk` matches the registered cost here.)
            let paid = registration_with_cost(OutletKind::Action, 10);
            let err = cross_context_economy_gate(&paid, Amount::new(10))
                .expect_err("a paid Action must be rejected zero-escrow");
            assert!(
                matches!(
                    err,
                    InvocationError::CrossContextPaidActionUnsupported { .. }
                ),
                "got {err:?}"
            );

            // Zero-cost Action + zero cost_per_chunk → accepted.
            cross_context_economy_gate(
                &registration_with_cost(OutletKind::Action, 0),
                Amount::new(0),
            )
            .expect("zero-cost Action proceeds");
            // Query (no cost) + zero cost_per_chunk → accepted.
            cross_context_economy_gate(
                &registration_with_cost(OutletKind::Query, 0),
                Amount::new(0),
            )
            .expect("Query proceeds");
        }

        /// FIX 2 — split-source / paid-best-effort bypass. A registration with
        /// `cost == 0` but a positive BILLED `cost_per_chunk` is REJECTED (not
        /// silently billed): the gate is enforced on the value that actually
        /// drives billing, not only the declared registration cost. The
        /// symmetric case (registered cost > 0 but `cost_per_chunk == 0`) is
        /// likewise rejected — either positive value trips the zero-escrow gate.
        #[test]
        fn fix2_zero_registered_cost_with_positive_cost_per_chunk_rejected() {
            use scp_protocol::economy::types::Amount;

            // Zero registered cost, positive billed cost_per_chunk → REJECTED.
            let zero_cost = registration_with_cost(OutletKind::Action, 0);
            let err = cross_context_economy_gate(&zero_cost, Amount::new(7)).expect_err(
                "a zero registered cost with a positive cost_per_chunk must be rejected",
            );
            assert!(
                matches!(
                    err,
                    InvocationError::CrossContextPaidActionUnsupported { .. }
                ),
                "the billed value drives the zero-escrow gate; got {err:?}"
            );

            // Positive registered cost, zero cost_per_chunk → also REJECTED
            // (paid registration cannot be smuggled through as zero-escrow).
            let paid = registration_with_cost(OutletKind::Action, 5);
            assert!(
                matches!(
                    cross_context_economy_gate(&paid, Amount::new(0)),
                    Err(InvocationError::CrossContextPaidActionUnsupported { .. })
                ),
                "a positive registered cost is rejected regardless of cost_per_chunk"
            );

            // Both zero → the only accepted shape.
            cross_context_economy_gate(&zero_cost, Amount::new(0))
                .expect("both zero is the only accepted zero-escrow shape");
        }

        // ---- FIX 3: terminal-less truncation — B drops its sender with no
        //             terminal → A's last chunk is a synthesized 6160.

        #[tokio::test]
        async fn fix3_data_only_without_terminal_synthesizes_transport_fault() {
            let op = operator_key();
            // A Data-only sequence whose producer drops the inner sender with NO
            // terminal chunk — models B's pump collapsing at the terminal chunk
            // (`try_build_signed_chunk` → `None` on an operator-signer failure).
            let chunks = vec![
                sign_chunk(
                    &op,
                    B_CTX,
                    OUTLET,
                    &CB,
                    0,
                    ChunkPayload::Data {
                        value: serde_json::json!({ "result": 0 }),
                    },
                ),
                sign_chunk(
                    &op,
                    B_CTX,
                    OUTLET,
                    &CB,
                    1,
                    ChunkPayload::Data {
                        value: serde_json::json!({ "result": 1 }),
                    },
                ),
            ];
            let (received, _a_log, _a_bytes) = drive_bridge(
                chunks,
                pinned_descriptor(&op),
                permissive_schema(),
                None,
                None,
            )
            .await;
            // A never truncates after a non-terminal Data: the two Data chunks
            // are followed by a SYNTHESIZED terminal transport-fault at the next
            // sequence (§5.4.5 terminal guarantee).
            assert_eq!(received.len(), 3, "two Data + one synthesized terminal");
            assert!(matches!(received[0].payload, ChunkPayload::Data { .. }));
            assert!(matches!(received[1].payload, ChunkPayload::Data { .. }));
            assert_terminal_error(received.last().unwrap(), CODE_TRANSPORT_FAULT);
            assert_eq!(
                received.last().unwrap().sequence,
                2,
                "the synthesized terminal is at last_delivered_sequence + 1"
            );
        }

        // ---- FIX 4: unbounded reassembly — an unbilled Progress flood is
        //             terminated at the retained-chunk cap with a 6160.

        #[tokio::test]
        async fn fix4_overlong_stream_terminated_with_transport_fault() {
            // A deliberately small retained-chunk cap so the test exercises the
            // ceiling without emitting a million chunks.
            const CAP: usize = 3;
            let op = operator_key();
            let (a_log, _a_bytes) = fresh_a_log().await;
            let a_dyn: Arc<dyn ContextEventLogProvider> = a_log.clone();
            let (inner_tx, inner_rx) = mpsc::channel::<OutletStreamChunk>(1);
            let (outer_tx, mut outer_rx) = mpsc::channel::<ForwardedStreamFrame>(1);
            let bridge = tokio::spawn(run_cross_context_bridge(
                inner_rx,
                outer_tx,
                pinned_descriptor(&op),
                permissive_schema(),
                None,
                a_dyn,
                A_CTX.to_owned(),
                DID::from(INVOKER),
                RID,
                OUTLET.to_owned(),
                "input-hash".to_owned(),
                3,
                0,
                CAP,
                None,
            ));

            // Flood the bridge with UNBILLED Progress chunks (never terminal),
            // far past the cap — the pre-fix bridge would retain all of them.
            let producer = {
                let op = op.clone();
                tokio::spawn(async move {
                    for seq in 0..1_000u64 {
                        let chunk = sign_chunk(
                            &op,
                            B_CTX,
                            OUTLET,
                            &CB,
                            seq,
                            ChunkPayload::Progress { pct: 0, note: None },
                        );
                        if inner_tx.send(chunk).await.is_err() {
                            break;
                        }
                    }
                })
            };

            let mut received = Vec::new();
            while let Some(frame) = outer_rx.recv().await {
                received.push(frame.chunk);
            }
            let _ = producer.await;
            bridge.await.expect("bridge");

            // The retained snapshot never grew unboundedly: the stream is
            // terminated with a transport-fault once the cap is reached.
            assert!(
                received.len() <= CAP + 1,
                "retained chunks + terminal are bounded by the cap; got {}",
                received.len()
            );
            assert_terminal_error(received.last().unwrap(), CODE_TRANSPORT_FAULT);
        }

        // ---- FIX 5: cross-stream replay — a chunk validly signed for a
        //             DIFFERENT request_id is rejected at the crossing.

        #[tokio::test]
        async fn fix5_chunk_with_foreign_request_id_rejected() {
            // A chunk VALIDLY signed by B's operator for a DIFFERENT stream
            // (request_id RID2) — same outlet, same caveats_binding, same
            // operator key — i.e. a genuine chunk from another same-outlet stream.
            const RID2: RequestId = [0xCD; 16];
            let op = operator_key();
            let payload = ChunkPayload::Data {
                value: serde_json::json!({ "result": 1 }),
            };
            let preimage = compute_chunk_sig_preimage(B_CTX, OUTLET, &RID2, 0, &CB, &payload)
                .expect("preimage");
            let sig = op.sign(&preimage).to_bytes();
            let foreign = OutletStreamChunk {
                request_id: RID2,
                sequence: 0,
                payload,
                sig,
            };

            // Its operator signature IS valid for its own stream (RID2)...
            assert!(
                scp_protocol::context::outlets::stream::verify_chunk_signature(
                    &foreign,
                    &op.verifying_key(),
                    B_CTX,
                    OUTLET,
                    &CB,
                ),
                "the chunk carries a valid operator signature for its own stream (RID2)"
            );
            // ...but the crossing pins request_id RID, so verification REJECTS it
            // — the rejection is due to the foreign request_id, not a bad sig.
            assert!(
                !verify_forwarded_chunk(&pinned_descriptor(&op), &foreign),
                "a chunk asserting a request_id other than the pinned one must NOT verify"
            );

            // End-to-end: the bridge emits the AC11 Authorization-class terminal.
            let (received, _a_log, _a_bytes) = drive_bridge(
                vec![foreign],
                pinned_descriptor(&op),
                permissive_schema(),
                None,
                None,
            )
            .await;
            assert_terminal_error(received.last().unwrap(), CODE_AUTHORIZATION_DENIED);
        }

        // -----------------------------------------------------------------
        // SCP-OUT-044 — per-sender base_sequence allocated at consumption on
        // the cross-context send hop via the ADR-049 §8 SequenceReservation.
        // -----------------------------------------------------------------

        /// Builds a bare (unsigned) Data chunk at `sequence`. `forward_frame`
        /// never verifies signatures — it stamps the send-seq anchor and
        /// forwards — so an unsigned chunk exercises the allocator directly.
        fn data_chunk(sequence: u64) -> OutletStreamChunk {
            OutletStreamChunk {
                request_id: RID,
                sequence,
                payload: ChunkPayload::Data {
                    value: serde_json::json!({ "n": sequence }),
                },
                sig: [0u8; 64],
            }
        }

        /// AC2 — the per-sender `base_sequence` is a strictly `+1`-monotone
        /// `u64` across a 5-chunk send, 1-based (first reservation → 1). The
        /// underlying chunk is forwarded unmodified.
        #[tokio::test]
        async fn out044_forward_frame_allocates_monotone_base_sequence() {
            let (tx, mut rx) = mpsc::channel::<ForwardedStreamFrame>(8);
            let mut tracker = crate::context::actor::SendSequenceTracker::new();

            for seq in 0..5u64 {
                assert!(
                    forward_frame(&tx, &mut tracker, &data_chunk(seq)).await,
                    "a send into an open channel must succeed and commit the reservation"
                );
            }
            drop(tx);

            let mut got = Vec::new();
            while let Some(frame) = rx.recv().await {
                got.push((frame.base_sequence, frame.chunk.sequence));
            }

            assert_eq!(got.len(), 5, "all five frames delivered");
            for (i, (base, chunk_seq)) in got.iter().enumerate() {
                assert_eq!(
                    *base,
                    (i as u64) + 1,
                    "base_sequence is per-sender 1-based, +1 per forwarded chunk"
                );
                assert_eq!(
                    *chunk_seq, i as u64,
                    "the underlying operator chunk is forwarded unmodified"
                );
            }
            for w in got.windows(2) {
                assert_eq!(
                    w[1].0,
                    w[0].0 + 1,
                    "strict +1 monotonicity across the 5-chunk send"
                );
            }
            assert_eq!(
                tracker.last_issued(),
                5,
                "all five reservations committed — high-water mark at 5"
            );
        }

        /// AC3 — a send that fails BEFORE `commit()` (A stopped consuming)
        /// rolls the reservation back via `Drop`; the next allocation reuses
        /// the freed number, so no send-sequence gap is burned. Mirrors
        /// `sequence.rs::reserve_drop_reserve_reuses_freed_number`.
        #[tokio::test]
        async fn out044_forward_frame_rolls_back_on_send_failure_and_reuses_sequence() {
            let mut tracker = crate::context::actor::SendSequenceTracker::new();

            // Drop the receiver FIRST so the send fails; `forward_frame` returns
            // false and its `SequenceReservation` drops WITHOUT commit → rollback.
            {
                let (tx, rx) = mpsc::channel::<ForwardedStreamFrame>(1);
                drop(rx);
                assert!(
                    !forward_frame(&tx, &mut tracker, &data_chunk(0)).await,
                    "a send into a closed channel must fail (A stopped consuming)"
                );
            }
            assert_eq!(
                tracker.last_issued(),
                0,
                "the failed send rolled the reservation back — no gap burned"
            );

            // A fresh open channel: the next allocation REUSES the freed number.
            let (tx2, mut rx2) = mpsc::channel::<ForwardedStreamFrame>(1);
            assert!(
                forward_frame(&tx2, &mut tracker, &data_chunk(0)).await,
                "the retry send on a fresh channel must succeed"
            );
            let frame = rx2.recv().await.expect("frame delivered on the retry");
            assert_eq!(
                frame.base_sequence, 1,
                "the rolled-back sequence (1) is reused on the next allocation — no gap"
            );
            assert_eq!(tracker.last_issued(), 1, "high-water mark committed at 1");
        }

        /// AC5 — the SAME-CONTEXT stream path is UNCHANGED: `invoke_outlet`
        /// still returns a BARE `mpsc::Receiver<OutletStreamChunk>` with NO
        /// `base_sequence` frame wrapper (allocate-at-consumption applies ONLY
        /// to the cross-context hop where the gap-detector is load-bearing).
        /// Compile-level proof: the explicit annotation fails to compile if the
        /// same-context return type drifts to a frame. The existing
        /// same-context runtime drain tests are the behavioural regression.
        #[allow(dead_code)]
        async fn out044_same_context_returns_bare_chunks(
            context: &ContextHandle,
            registry: &OutletRegistry,
            role_state: &ContextRoleState,
            outlet_id: &OutletId,
            invoker_did: &DID,
        ) {
            let out: Result<mpsc::Receiver<OutletStreamChunk>, InvocationError> =
                invoke_outlet::<NoopExecutor>(
                    context,
                    registry,
                    role_state,
                    outlet_id,
                    serde_json::json!({}),
                    invoker_did,
                    None,
                    Arc::new(NoopExecutor),
                    None,
                    None,
                    None,
                    None,
                    [0u8; 32],
                )
                .await;
            drop(out);
        }
    }

    // =====================================================================
    // SCP-OUT-036 AC10 — seal one chunk for A over the EXISTING MLS transport
    // =====================================================================
    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    mod cross_context_036_seal {
        use std::sync::Arc;

        use ed25519_dalek::{Signer as _, SigningKey};

        use scp_protocol::context::outlets::stream::{
            ChunkPayload, OutletStreamChunk, compute_chunk_sig_preimage, verify_chunk_signature,
        };

        const B_CTX: &str = "ctx-b-036-seal";
        const OUTLET: &str = "calculator";
        const CB: [u8; 32] = [0x11; 32];
        const RID: [u8; 16] = [0xAB; 16];

        fn operator_signed_chunk() -> OutletStreamChunk {
            let operator = SigningKey::from_bytes(&[0x5c; 32]);
            let payload = ChunkPayload::Data {
                value: serde_json::json!({ "result": 7 }),
            };
            let preimage =
                compute_chunk_sig_preimage(B_CTX, OUTLET, &RID, 0, &CB, &payload).unwrap();
            let sig = operator.sign(&preimage).to_bytes();
            OutletStreamChunk {
                request_id: RID,
                sequence: 0,
                payload,
                sig,
            }
        }

        /// AC10 — seal ONE operator-signed chunk as an A-context MLS application
        /// message via the EXISTING `MlsCryptoProvider::seal`/`open` (no invented
        /// envelope): (a) a non-A-member cannot decrypt it, (b) an A member
        /// recovers the chunk with B's operator signature INTACT and verifying
        /// against B's pinned `context_id` — never re-signed by the bridge.
        #[test]
        fn ac10_seal_for_a_preserves_operator_sig() {
            use crate::crypto::mls::provider::MlsCryptoProvider;
            use crate::crypto::mls::two_party_test_support::stand_up_two_party;
            use crate::envelope::inner::sign::create_inner_envelope_raw;
            use crate::envelope::inner::{
                InnerEnvelopeParams, MessageType, SCP_INNER_ENVELOPE_VERSION,
            };
            use scp_protocol::context::builder::OpenResult;

            let a_ctx_str = "a-ctx-036-seal";
            let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAl";
            let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
            // Alice (sealer, A member) + Bob (opener, A member) share a real MLS
            // group for the receiving context A.
            let (alice, bob, a_ctx_bytes) = stand_up_two_party(a_ctx_str, alice_did, bob_did);
            let routing_id = a_ctx_bytes.to_vec();

            let chunk = operator_signed_chunk();
            let operator_pk = SigningKey::from_bytes(&[0x5c; 32]).verifying_key();
            // The chunk bytes are the InnerEnvelope payload — the bridge wraps
            // the still-operator-signed chunk; it does NOT invent a new envelope.
            let chunk_bytes = serde_json::to_vec(&chunk).unwrap();

            // The forwarding member (Alice) signs the OUTER inner-envelope with
            // her own key; the CHUNK inside keeps B's operator signature.
            let sender_key = SigningKey::from_bytes(&[0x24; 32]);
            let build_inner = |seq: u64| {
                let params = InnerEnvelopeParams {
                    version: SCP_INNER_ENVELOPE_VERSION,
                    context_id: a_ctx_str,
                    sender_did: alice_did,
                    epoch: 0,
                    generation: 0,
                    sequence: seq,
                    timestamp: 1_700_000_000,
                    message_type: MessageType::Content,
                    payload: &chunk_bytes,
                    provenance: None,
                    signing_key_id: scp_did::SigningKeyId::Active,
                };
                create_inner_envelope_raw(&params, &sender_key).unwrap()
            };

            // Two independently-sealed copies (MLS forward secrecy consumes the
            // per-message secret on first open of a given ciphertext).
            let sealed_for_outsider = alice
                .seal(&a_ctx_bytes, &build_inner(0), &routing_id, 300)
                .unwrap();
            let sealed_for_member = alice
                .seal(&a_ctx_bytes, &build_inner(1), &routing_id, 300)
                .unwrap();

            // (a) A non-A-member (fresh provider, no A group key) CANNOT decrypt.
            let outsider = Arc::new(MlsCryptoProvider::new(
                "did:dht:z6MkOutsiderOutsiderOutsiderOutsiderOut".to_owned(),
                Arc::new(scp_clock::SystemClock),
            ));
            assert!(
                outsider
                    .open(&a_ctx_bytes, a_ctx_str, &sealed_for_outsider)
                    .is_err(),
                "a non-A-member holding no A group key must not decrypt the sealed chunk"
            );

            // (b) An A member decrypts and recovers the chunk with B's operator
            // signature intact and verifying against B's PINNED context_id.
            let opened = bob
                .open(&a_ctx_bytes, a_ctx_str, &sealed_for_member)
                .unwrap();
            let recovered_bytes = match opened {
                OpenResult::Application(env) => env.inner.payload,
                other => panic!("expected Application, got {other:?}"),
            };
            // The inner-envelope payload is length-padded for traffic-analysis
            // resistance, so stream-deserialize the FIRST JSON value and ignore
            // trailing padding bytes.
            let recovered: OutletStreamChunk = {
                use serde::Deserialize as _;
                let mut de = serde_json::Deserializer::from_slice(&recovered_bytes);
                OutletStreamChunk::deserialize(&mut de).unwrap()
            };
            assert_eq!(
                recovered, chunk,
                "A member recovers the exact operator chunk"
            );
            assert!(
                verify_chunk_signature(&recovered, &operator_pk, B_CTX, OUTLET, &CB),
                "B's operator SCP-OUTLET-CHUNK-SIG-V1 signature is preserved end-to-end \
                 (never re-signed by the bridge) and verifies against B's pinned context_id"
            );
        }
    }
}
