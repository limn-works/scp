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
use std::time::Duration;

use super::lifecycle::{
    DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS, ToolInvokedEvent, ToolStatus, sha256_json,
};
use super::registry::ToolRegistry;
use super::schema::validate_value_against_schema;
use super::{DID, ToolId};
use crate::context::roles::{Capability, ContextRoleState};
use crate::context::{ContextHandle, ContextState};

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
/// 5. Calls the tool implementation via the `executor` function.
/// 6. Validates output against the tool's output schema.
/// 7. Builds a [`ToolInvokedEvent`] for the caller to append to the event log.
/// 8. Returns the tool output.
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
/// Returns [`InvocationError`] on protocol-level validation failures.
///
/// See ADR-010 acceptance criterion 3 (`invoke_tool`).
#[allow(clippy::too_many_arguments)]
pub async fn invoke_tool<F, Fut>(
    context: &ContextHandle,
    registry: &ToolRegistry,
    role_state: &ContextRoleState,
    tool_id: &ToolId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: F,
) -> Result<(serde_json::Value, ToolInvokedEvent), InvocationError>
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

    // 5. Execute the tool with timeout.
    let effective_timeout = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS).min(MAX_TIMEOUT_MS);
    let timeout_duration = Duration::from_millis(u64::from(effective_timeout));

    let execution_result = tokio::time::timeout(timeout_duration, executor(input.clone())).await;

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

    // 7. Build event payload.
    let execution_time_ms = elapsed_ms(start);
    let input_hash = sha256_json(&input);
    let output_hash = Some(sha256_json(&output));

    let event = ToolInvokedEvent {
        request_id: uuid::Uuid::new_v4().to_string(),
        tool_id: tool_id.to_owned(),
        invoker_did: invoker_did.clone(),
        status: ToolStatus::Success,
        execution_time_ms,
        input_hash,
        output_hash,
    };

    // 8. Return tool output and event.
    Ok((output, event))
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
/// timeout, or cancellation.
#[allow(clippy::too_many_arguments)]
pub async fn invoke_tool_with_cancellation<F, Fut, C, CFut>(
    context: &ContextHandle,
    registry: &ToolRegistry,
    role_state: &ContextRoleState,
    tool_id: &ToolId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: F,
    cancellation: C,
) -> Result<(serde_json::Value, ToolInvokedEvent), InvocationError>
where
    F: FnOnce(serde_json::Value) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
    C: FnOnce() -> CFut,
    CFut: Future<Output = ()>,
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
        Ok(Err(msg)) if msg == "cancelled" => {
            return Err(InvocationError::Cancelled);
        }
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

    // 7. Build event payload.
    let execution_time_ms = elapsed_ms(start);
    let input_hash = sha256_json(&input);
    let output_hash = Some(sha256_json(&output));

    let event = ToolInvokedEvent {
        request_id: uuid::Uuid::new_v4().to_string(),
        tool_id: tool_id.to_owned(),
        invoker_did: invoker_did.clone(),
        status: ToolStatus::Success,
        execution_time_ms,
        input_hash,
        output_hash,
    };

    Ok((output, event))
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::context::ContextParams;
    use crate::context::roles::{CapabilityCeiling, ContextRoleState};
    use crate::context::tools::registry::{ToolRegistration, ToolSchema, register_tool};

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
        ContextRoleState::new("ctx-test", creator_did, test_ceiling(), vec![]).unwrap()
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
            economic_metadata: None,
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
        )
        .await;

        assert!(result.is_ok(), "invoke_tool should succeed: {result:?}");
        let (output, event) = result.unwrap();
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

        let (output, event) = invoke_tool(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            input.clone(),
            &DID::from(creator_did),
            None,
            add_executor,
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
}
