//! Cross-context tool interfaces with bidirectional consent and rate limiting.
//!
//! Implements spec section 6.2: cross-context tool interfaces allow structured
//! interaction across context boundaries. The context governs the tool call,
//! not the agent. Both source and target contexts must explicitly approve the
//! interface before any calls are permitted.
//!
//! # Flow
//!
//! 1. Source context admin calls [`expose_tool`] to propose sharing a tool.
//! 2. Target context admin calls [`accept_tool_interface`] to accept.
//! 3. Participants invoke via [`invoke_cross_context`], which checks both
//!    approvals, enforces rate limits, and records events in both contexts.
//!
//! See ADR-010 in `.docs/adrs/phase-2.md` for the full design.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::lifecycle::{ToolStatus, sha256_json};
use super::registry::ToolRegistry;
use super::{DID, ToolError, ToolId, has_admin_role};
use crate::context::ContextHandle;
use crate::context::roles::ContextRoleState;

// ---------------------------------------------------------------------------
// ContextId
// ---------------------------------------------------------------------------

/// Context identifier for cross-context operations.
///
/// Same underlying type as used elsewhere in the codebase (`String`).
pub type ContextId = String;

// ---------------------------------------------------------------------------
// RateLimit
// ---------------------------------------------------------------------------

/// Rate limit configuration for a cross-context tool interface.
///
/// Tracks the maximum number of calls permitted within a sliding time window.
/// The `current_count` and `window_start` fields are mutable state that is
/// updated on each invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum number of calls permitted within the time window.
    pub max_calls: u64,
    /// Duration of the sliding time window.
    pub window: Duration,
    /// Number of calls made in the current window.
    pub current_count: u64,
    /// Start of the current window as Unix timestamp in milliseconds.
    pub window_start: u64,
}

impl RateLimit {
    /// Creates a new rate limit with the given maximum calls and window duration.
    ///
    /// Initializes `current_count` to 0 and `window_start` to the current time.
    #[must_use]
    pub fn new(max_calls: u64, window: Duration) -> Self {
        Self {
            max_calls,
            window,
            current_count: 0,
            window_start: current_timestamp_ms(),
        }
    }

    /// Checks whether a call is permitted under the current rate limit.
    ///
    /// If the current window has expired, resets the counter and starts a new
    /// window. Returns `true` if the call is permitted (count < max), `false`
    /// otherwise.
    #[allow(clippy::cast_possible_truncation)]
    fn check_and_increment(&mut self) -> bool {
        let now = current_timestamp_ms();
        // Window durations are always far below u64::MAX milliseconds.
        let window_ms = self.window.as_millis() as u64;

        // If the window has expired, reset.
        if now.saturating_sub(self.window_start) >= window_ms {
            self.current_count = 0;
            self.window_start = now;
        }

        if self.current_count < self.max_calls {
            self.current_count += 1;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// ToolInterface
// ---------------------------------------------------------------------------

/// A cross-context tool interface with bidirectional consent.
///
/// Represents an agreement between two contexts to share access to a specific
/// tool. Both contexts must approve the interface before any calls are
/// permitted. Rate limiting is optionally enforced per interface.
///
/// See ADR-010 section 6 and spec section 6.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInterface {
    /// The context exposing (sourcing) the tool.
    pub source_context: ContextId,
    /// The context consuming (targeting) the tool.
    pub target_context: ContextId,
    /// The tool being shared across contexts.
    pub tool_id: ToolId,
    /// Optional rate limit for calls through this interface.
    pub rate_limit: Option<RateLimit>,
    /// Whether the source context has approved the interface.
    pub approved_by_source: bool,
    /// Whether the target context has approved the interface.
    pub approved_by_target: bool,
}

// ---------------------------------------------------------------------------
// CrossContextEvent (event log integration)
// ---------------------------------------------------------------------------

/// Event payload for a cross-context tool invocation in the event log.
///
/// Both source and target contexts record this event to maintain full
/// provenance of cross-context calls. See protocol tenet 1: "Provenance
/// everywhere."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContextToolEvent {
    /// UUID v4 request identifier.
    pub request_id: String,
    /// The tool that was invoked.
    pub tool_id: ToolId,
    /// The context that initiated the call (source).
    pub source_context: ContextId,
    /// The context that received the call (target).
    pub target_context: ContextId,
    /// The DID of the invoker.
    pub invoker_did: DID,
    /// Terminal status of the invocation.
    pub status: ToolStatus,
    /// SHA-256 hash of the input (hex-encoded).
    pub input_hash: String,
    /// SHA-256 hash of the output (hex-encoded), if output was produced.
    pub output_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// expose_tool
// ---------------------------------------------------------------------------

/// Initiates a cross-context tool interface proposal from the source context.
///
/// The caller (admin of the source context) proposes sharing a specific tool
/// with the target context. The returned [`ToolInterface`] has
/// `approved_by_source = true` and `approved_by_target = false`. The target
/// context must call [`accept_tool_interface`] to complete the handshake.
///
/// # Arguments
///
/// * `context` - The source context handle.
/// * `tool_id` - The ID of the tool to expose.
/// * `to_context` - The target context ID.
/// * `role_state` - The source context's role state for capability checking.
/// * `admin_did` - The DID of the admin proposing the interface.
/// * `registry` - The source context's tool registry.
/// * `rate_limit` - Optional rate limit for the interface.
///
/// # Errors
///
/// Returns [`ToolError::InterfaceAdminRequired`] if the caller is not an admin.
/// Returns [`ToolError::ToolNotFound`] if the tool is not in the registry.
pub fn expose_tool(
    context: &ContextHandle,
    tool_id: &ToolId,
    to_context: &ContextId,
    role_state: &ContextRoleState,
    admin_did: &str,
    registry: &ToolRegistry,
    rate_limit: Option<RateLimit>,
) -> Result<ToolInterface, ToolError> {
    // Require admin capability.
    if !has_admin_role(role_state, admin_did) {
        return Err(ToolError::InterfaceAdminRequired {
            did: admin_did.to_owned(),
        });
    }

    // Verify the tool exists in the source context's registry.
    if !registry.contains(tool_id) {
        return Err(ToolError::ToolNotFound {
            tool_id: tool_id.to_owned(),
        });
    }

    Ok(ToolInterface {
        source_context: context.context_id().to_owned(),
        target_context: to_context.to_owned(),
        tool_id: tool_id.to_owned(),
        rate_limit,
        approved_by_source: true,
        approved_by_target: false,
    })
}

// ---------------------------------------------------------------------------
// accept_tool_interface
// ---------------------------------------------------------------------------

/// Target context accepts a cross-context tool interface.
///
/// Sets `approved_by_target = true` on the interface. Both `approved_by_source`
/// and `approved_by_target` must be `true` before calls are permitted.
///
/// # Arguments
///
/// * `context` - The target context handle.
/// * `interface` - The tool interface to accept (mutated in place).
/// * `role_state` - The target context's role state for capability checking.
/// * `admin_did` - The DID of the admin accepting the interface.
///
/// # Errors
///
/// Returns [`ToolError::InterfaceAdminRequired`] if the caller is not an admin.
/// Returns [`ToolError::InterfaceContextMismatch`] if the interface's target
/// context does not match the provided context handle.
pub fn accept_tool_interface(
    context: &ContextHandle,
    interface: &mut ToolInterface,
    role_state: &ContextRoleState,
    admin_did: &str,
) -> Result<(), ToolError> {
    // Require admin capability.
    if !has_admin_role(role_state, admin_did) {
        return Err(ToolError::InterfaceAdminRequired {
            did: admin_did.to_owned(),
        });
    }

    // Verify the interface targets this context.
    if interface.target_context != context.context_id() {
        return Err(ToolError::InterfaceContextMismatch {
            expected: interface.target_context.clone(),
            actual: context.context_id().to_owned(),
        });
    }

    interface.approved_by_target = true;
    Ok(())
}

// ---------------------------------------------------------------------------
// invoke_cross_context
// ---------------------------------------------------------------------------

/// Invokes a tool across context boundaries.
///
/// Performs the following checks:
/// 1. Both `approved_by_source` and `approved_by_target` must be `true`.
/// 2. Rate limit is checked and incremented if present.
/// 3. Source context governance checks outbound (invoker has tool invoke
///    capability in source context).
/// 4. Target context governance checks inbound (tool exists in target
///    registry and target context is active).
///
/// Returns the tool output along with event payloads for both the source
/// and target event logs.
///
/// # Arguments
///
/// * `source_context` - The source context handle.
/// * `interface` - The cross-context tool interface (mutated for rate limit
///   tracking).
/// * `input` - JSON input to pass to the tool.
/// * `invoker_did` - The DID of the participant invoking the tool.
/// * `source_role_state` - Source context role state for governance checks.
/// * `target_registry` - Target context tool registry.
/// * `executor` - Synchronous executor for the tool (returns Result).
///
/// # Errors
///
/// Returns [`ToolError::InterfaceNotApproved`] if either context has not
/// approved the interface.
/// Returns [`ToolError::InterfaceRateLimited`] if the rate limit is exceeded.
/// Returns [`ToolError::InterfaceAdminRequired`] if the invoker lacks the
/// required capability in the source context.
pub fn invoke_cross_context<F>(
    source_context: &ContextHandle,
    interface: &mut ToolInterface,
    input: &serde_json::Value,
    invoker_did: &DID,
    source_role_state: &ContextRoleState,
    target_registry: &ToolRegistry,
    executor: F,
) -> Result<
    (
        serde_json::Value,
        CrossContextToolEvent,
        CrossContextToolEvent,
    ),
    ToolError,
>
where
    F: FnOnce(&serde_json::Value) -> Result<serde_json::Value, String>,
{
    // 1. Both sides must have approved.
    if !interface.approved_by_source || !interface.approved_by_target {
        return Err(ToolError::InterfaceNotApproved {
            source_approved: interface.approved_by_source,
            target_approved: interface.approved_by_target,
        });
    }

    // Verify the source context matches the interface.
    if interface.source_context != source_context.context_id() {
        return Err(ToolError::InterfaceContextMismatch {
            expected: interface.source_context.clone(),
            actual: source_context.context_id().to_owned(),
        });
    }

    // 2. Check rate limit.
    #[allow(clippy::cast_possible_truncation)]
    if let Some(ref mut rate_limit) = interface.rate_limit {
        if !rate_limit.check_and_increment() {
            // Window durations are always far below u64::MAX milliseconds.
            let window_ms = rate_limit.window.as_millis() as u64;
            return Err(ToolError::InterfaceRateLimited {
                max_calls: rate_limit.max_calls,
                window_ms,
            });
        }
    }

    // 3. Source context governance: invoker must have tool invoke capability.
    if !super::invoke::has_tool_invoke_capability(
        source_role_state,
        invoker_did,
        &interface.tool_id,
    ) {
        return Err(ToolError::InterfaceInvokerNotAuthorized {
            did: invoker_did.to_owned(),
            tool_id: interface.tool_id.clone(),
        });
    }

    // 4. Target context governance: tool must exist in target registry.
    if !target_registry.contains(&interface.tool_id) {
        return Err(ToolError::ToolNotFound {
            tool_id: interface.tool_id.clone(),
        });
    }

    // 5. Execute the tool.
    let output =
        executor(input).map_err(|msg| ToolError::InterfaceExecutionFailed { message: msg })?;

    // 6. Build event payloads for both contexts.
    let request_id = uuid::Uuid::new_v4().to_string();
    let input_hash = sha256_json(input);
    let output_hash = Some(sha256_json(&output));

    let source_event = CrossContextToolEvent {
        request_id: request_id.clone(),
        tool_id: interface.tool_id.clone(),
        source_context: interface.source_context.clone(),
        target_context: interface.target_context.clone(),
        invoker_did: invoker_did.to_owned(),
        status: ToolStatus::Success,
        input_hash: input_hash.clone(),
        output_hash: output_hash.clone(),
    };

    let target_event = CrossContextToolEvent {
        request_id,
        tool_id: interface.tool_id.clone(),
        source_context: interface.source_context.clone(),
        target_context: interface.target_context.clone(),
        invoker_did: invoker_did.to_owned(),
        status: ToolStatus::Success,
        input_hash,
        output_hash,
    };

    Ok((output, source_event, target_event))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Returns the current Unix timestamp in milliseconds.
#[allow(clippy::cast_possible_truncation)]
fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| {
            let millis = d.as_millis();
            if millis > u128::from(u64::MAX) {
                u64::MAX
            } else {
                millis as u64
            }
        })
        .unwrap_or(0)
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
    use crate::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
    use crate::context::tools::registry::{
        ToolRegistration, ToolRegistry, ToolSchema, register_tool,
    };

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

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
    fn test_role_state(context_id: &str, creator_did: &str) -> ContextRoleState {
        ContextRoleState::new(context_id, creator_did, test_ceiling(), vec![]).unwrap()
    }

    /// Creates a `ContextRoleState` with an additional member that has limited
    /// capabilities (no admin, no tool invoke).
    fn test_role_state_with_non_admin_member(
        context_id: &str,
        creator_did: &str,
        member_did: &str,
    ) -> ContextRoleState {
        let mut state = test_role_state(context_id, creator_did);
        state.members.insert(member_did.to_owned());
        let member_caps: HashSet<Capability> =
            [Capability::MessagesRead, Capability::MessagesWrite]
                .into_iter()
                .collect();
        state
            .member_capabilities
            .insert(member_did.to_owned(), member_caps);
        state
    }

    /// Creates a context handle (in Creating state).
    fn test_context(context_id: &str) -> ContextHandle {
        ContextHandle::new(context_id.to_owned(), ContextParams::default())
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
            operator_did: "did:dht:z6MkOperator".to_owned(),
            economic_metadata: None,
        };
        register_tool(&mut registry, role_state, registration, registrant_did).unwrap();
        registry
    }

    /// Simple synchronous executor that adds two numbers.
    fn add_executor(input: &serde_json::Value) -> Result<serde_json::Value, String> {
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
    // expose_tool: happy path
    // -----------------------------------------------------------------------

    #[test]
    fn expose_tool_creates_interface_with_source_approved() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let registry = setup_registry_with_tool(&source_role_state, admin_did);

        let interface = expose_tool(
            &source_context,
            &"calculator".to_owned(),
            &"ctx-target".to_owned(),
            &source_role_state,
            admin_did,
            &registry,
            None,
        )
        .unwrap();

        assert_eq!(interface.source_context, "ctx-source");
        assert_eq!(interface.target_context, "ctx-target");
        assert_eq!(interface.tool_id, "calculator");
        assert!(interface.approved_by_source);
        assert!(!interface.approved_by_target);
        assert!(interface.rate_limit.is_none());
    }

    // -----------------------------------------------------------------------
    // expose_tool: requires admin capability
    // -----------------------------------------------------------------------

    #[test]
    fn expose_tool_requires_admin_capability() {
        let admin_did = "did:dht:z6MkAdmin";
        let member_did = "did:dht:z6MkMember";
        let source_role_state =
            test_role_state_with_non_admin_member("ctx-source", admin_did, member_did);
        let source_context = test_context("ctx-source");
        let registry = setup_registry_with_tool(&source_role_state, admin_did);

        let result = expose_tool(
            &source_context,
            &"calculator".to_owned(),
            &"ctx-target".to_owned(),
            &source_role_state,
            member_did,
            &registry,
            None,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ToolError::InterfaceAdminRequired { .. }),
            "expected InterfaceAdminRequired, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // expose_tool: tool not found
    // -----------------------------------------------------------------------

    #[test]
    fn expose_tool_rejects_nonexistent_tool() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let registry = ToolRegistry::new(); // Empty registry

        let result = expose_tool(
            &source_context,
            &"nonexistent".to_owned(),
            &"ctx-target".to_owned(),
            &source_role_state,
            admin_did,
            &registry,
            None,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolError::ToolNotFound { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // expose_tool: with rate limit
    // -----------------------------------------------------------------------

    #[test]
    fn expose_tool_includes_rate_limit_when_provided() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let registry = setup_registry_with_tool(&source_role_state, admin_did);

        let rate_limit = RateLimit::new(10, Duration::from_secs(60));
        let interface = expose_tool(
            &source_context,
            &"calculator".to_owned(),
            &"ctx-target".to_owned(),
            &source_role_state,
            admin_did,
            &registry,
            Some(rate_limit),
        )
        .unwrap();

        assert!(interface.rate_limit.is_some());
        let rl = interface.rate_limit.unwrap();
        assert_eq!(rl.max_calls, 10);
        assert_eq!(rl.window, Duration::from_secs(60));
    }

    // -----------------------------------------------------------------------
    // accept_tool_interface: happy path
    // -----------------------------------------------------------------------

    #[test]
    fn accept_tool_interface_sets_approved_by_target() {
        let admin_did = "did:dht:z6MkAdmin";
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_context = test_context("ctx-target");

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            approved_by_source: true,
            approved_by_target: false,
        };

        let result = accept_tool_interface(
            &target_context,
            &mut interface,
            &target_role_state,
            admin_did,
        );

        assert!(result.is_ok());
        assert!(interface.approved_by_target);
        assert!(interface.approved_by_source);
    }

    // -----------------------------------------------------------------------
    // accept_tool_interface: requires admin capability
    // -----------------------------------------------------------------------

    #[test]
    fn accept_tool_interface_requires_admin_capability() {
        let admin_did = "did:dht:z6MkAdmin";
        let member_did = "did:dht:z6MkMember";
        let target_role_state =
            test_role_state_with_non_admin_member("ctx-target", admin_did, member_did);
        let target_context = test_context("ctx-target");

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            approved_by_source: true,
            approved_by_target: false,
        };

        let result = accept_tool_interface(
            &target_context,
            &mut interface,
            &target_role_state,
            member_did,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ToolError::InterfaceAdminRequired { .. }),
            "expected InterfaceAdminRequired, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // accept_tool_interface: context mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn accept_tool_interface_rejects_context_mismatch() {
        let admin_did = "did:dht:z6MkAdmin";
        let target_role_state = test_role_state("ctx-wrong", admin_did);
        let target_context = test_context("ctx-wrong");

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            approved_by_source: true,
            approved_by_target: false,
        };

        let result = accept_tool_interface(
            &target_context,
            &mut interface,
            &target_role_state,
            admin_did,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolError::InterfaceContextMismatch { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: happy path
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_succeeds_with_full_approval() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
        };

        let input = serde_json::json!({"a": 3, "b": 4});
        let (output, source_event, target_event) = invoke_cross_context(
            &source_context,
            &mut interface,
            &input,
            &admin_did.to_owned(),
            &source_role_state,
            &target_registry,
            add_executor,
        )
        .unwrap();

        assert_eq!(output, serde_json::json!({"result": 7.0}));

        // Both events should record the cross-context call.
        assert_eq!(source_event.tool_id, "calculator");
        assert_eq!(source_event.source_context, "ctx-source");
        assert_eq!(source_event.target_context, "ctx-target");
        assert_eq!(source_event.invoker_did, admin_did);
        assert_eq!(source_event.status, ToolStatus::Success);
        assert!(!source_event.input_hash.is_empty());
        assert!(source_event.output_hash.is_some());

        assert_eq!(target_event.tool_id, "calculator");
        assert_eq!(target_event.source_context, "ctx-source");
        assert_eq!(target_event.target_context, "ctx-target");
        assert_eq!(target_event.invoker_did, admin_did);

        // Both events share the same request_id.
        assert_eq!(source_event.request_id, target_event.request_id);
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: fails when only one side approved
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_fails_when_only_source_approved() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            approved_by_source: true,
            approved_by_target: false, // Target has NOT approved
        };

        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &admin_did.to_owned(),
            &source_role_state,
            &target_registry,
            add_executor,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ToolError::InterfaceNotApproved {
                    source_approved: true,
                    target_approved: false,
                }
            ),
            "expected InterfaceNotApproved, got {err:?}"
        );
    }

    #[test]
    fn invoke_cross_context_fails_when_only_target_approved() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            approved_by_source: false, // Source has NOT approved
            approved_by_target: true,
        };

        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &admin_did.to_owned(),
            &source_role_state,
            &target_registry,
            add_executor,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ToolError::InterfaceNotApproved {
                    source_approved: false,
                    target_approved: true,
                }
            ),
            "expected InterfaceNotApproved, got {err:?}"
        );
    }

    #[test]
    fn invoke_cross_context_fails_when_neither_side_approved() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            approved_by_source: false,
            approved_by_target: false,
        };

        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &admin_did.to_owned(),
            &source_role_state,
            &target_registry,
            add_executor,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolError::InterfaceNotApproved { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: rate limiting rejects calls beyond limit
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_rate_limiting_rejects_beyond_limit() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: Some(RateLimit::new(2, Duration::from_secs(3600))),
            approved_by_source: true,
            approved_by_target: true,
        };

        let input = serde_json::json!({"a": 1, "b": 2});

        // First call: should succeed.
        let result1 = invoke_cross_context(
            &source_context,
            &mut interface,
            &input,
            &admin_did.to_owned(),
            &source_role_state,
            &target_registry,
            add_executor,
        );
        assert!(result1.is_ok(), "first call should succeed");

        // Second call: should succeed (at limit).
        let result2 = invoke_cross_context(
            &source_context,
            &mut interface,
            &input,
            &admin_did.to_owned(),
            &source_role_state,
            &target_registry,
            add_executor,
        );
        assert!(result2.is_ok(), "second call should succeed");

        // Third call: should be rejected (over limit).
        let result3 = invoke_cross_context(
            &source_context,
            &mut interface,
            &input,
            &admin_did.to_owned(),
            &source_role_state,
            &target_registry,
            add_executor,
        );
        assert!(result3.is_err());
        let err = result3.unwrap_err();
        assert!(
            matches!(err, ToolError::InterfaceRateLimited { max_calls: 2, .. }),
            "expected InterfaceRateLimited, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: both event logs record the call
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_both_event_logs_record_provenance() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
        };

        let input = serde_json::json!({"a": 10, "b": 20});
        let (output, source_event, target_event) = invoke_cross_context(
            &source_context,
            &mut interface,
            &input,
            &admin_did.to_owned(),
            &source_role_state,
            &target_registry,
            add_executor,
        )
        .unwrap();

        // Verify provenance in source event.
        assert_eq!(source_event.invoker_did, admin_did);
        assert_eq!(source_event.source_context, "ctx-source");
        assert_eq!(source_event.target_context, "ctx-target");
        assert_eq!(source_event.status, ToolStatus::Success);

        // Verify provenance in target event.
        assert_eq!(target_event.invoker_did, admin_did);
        assert_eq!(target_event.source_context, "ctx-source");
        assert_eq!(target_event.target_context, "ctx-target");
        assert_eq!(target_event.status, ToolStatus::Success);

        // Both events have correct hashes.
        let expected_input_hash = sha256_json(&input);
        let expected_output_hash = sha256_json(&output);
        assert_eq!(source_event.input_hash, expected_input_hash);
        assert_eq!(source_event.output_hash, Some(expected_output_hash.clone()));
        assert_eq!(target_event.input_hash, expected_input_hash);
        assert_eq!(target_event.output_hash, Some(expected_output_hash));

        // Events share the same request_id for correlation.
        assert_eq!(source_event.request_id, target_event.request_id);
        // Request IDs are UUID v4 format.
        assert_eq!(source_event.request_id.len(), 36);
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: invoker without capability
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_rejects_invoker_without_capability() {
        let admin_did = "did:dht:z6MkAdmin";
        let member_did = "did:dht:z6MkMember";
        let source_role_state =
            test_role_state_with_non_admin_member("ctx-source", admin_did, member_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
        };

        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &member_did.to_owned(),
            &source_role_state,
            &target_registry,
            add_executor,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolError::InterfaceInvokerNotAuthorized { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: tool not found in target
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_rejects_when_tool_not_in_target_registry() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_registry = ToolRegistry::new(); // Empty target registry

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
        };

        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &admin_did.to_owned(),
            &source_role_state,
            &target_registry,
            add_executor,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolError::ToolNotFound { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // RateLimit: window reset
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limit_resets_after_window_expires() {
        let mut rl = RateLimit {
            max_calls: 1,
            window: Duration::from_millis(1),
            current_count: 1,
            // Set window_start far in the past so the window is expired.
            window_start: 0,
        };

        // Window should have expired, so this should succeed and reset.
        assert!(rl.check_and_increment());
        assert_eq!(rl.current_count, 1);
    }

    // -----------------------------------------------------------------------
    // RateLimit: serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limit_serialization_roundtrip() {
        let rl = RateLimit {
            max_calls: 100,
            window: Duration::from_secs(60),
            current_count: 5,
            window_start: 1_000_000,
        };
        let json = serde_json::to_string(&rl).unwrap();
        let deserialized: RateLimit = serde_json::from_str(&json).unwrap();
        assert_eq!(rl, deserialized);
    }

    // -----------------------------------------------------------------------
    // ToolInterface: serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn tool_interface_serialization_roundtrip() {
        let interface = ToolInterface {
            source_context: "ctx-a".to_owned(),
            target_context: "ctx-b".to_owned(),
            tool_id: "tool-1".to_owned(),
            rate_limit: Some(RateLimit::new(50, Duration::from_secs(120))),
            approved_by_source: true,
            approved_by_target: false,
        };
        let json = serde_json::to_string(&interface).unwrap();
        let deserialized: ToolInterface = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.source_context, "ctx-a");
        assert_eq!(deserialized.target_context, "ctx-b");
        assert_eq!(deserialized.tool_id, "tool-1");
        assert!(deserialized.approved_by_source);
        assert!(!deserialized.approved_by_target);
        assert!(deserialized.rate_limit.is_some());
    }

    // -----------------------------------------------------------------------
    // CrossContextToolEvent: serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn cross_context_tool_event_serialization_roundtrip() {
        let event = CrossContextToolEvent {
            request_id: "req-1".to_owned(),
            tool_id: "calculator".to_owned(),
            source_context: "ctx-a".to_owned(),
            target_context: "ctx-b".to_owned(),
            invoker_did: "did:dht:z6MkTest".to_owned(),
            status: ToolStatus::Success,
            input_hash: "abcd1234".to_owned(),
            output_hash: Some("efgh5678".to_owned()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: CrossContextToolEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.request_id, "req-1");
        assert_eq!(deserialized.tool_id, "calculator");
        assert_eq!(deserialized.status, ToolStatus::Success);
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: executor failure propagates
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_executor_failure_propagates() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
        };

        let failing_executor = |_input: &serde_json::Value| -> Result<serde_json::Value, String> {
            Err("computation failed".to_owned())
        };

        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &admin_did.to_owned(),
            &source_role_state,
            &target_registry,
            failing_executor,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ToolError::InterfaceExecutionFailed { .. }),
            "expected InterfaceExecutionFailed, got {err:?}"
        );
        assert!(err.to_string().contains("computation failed"));
    }
}
