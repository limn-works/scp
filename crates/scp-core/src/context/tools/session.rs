//! Stateful tool sessions (spec section 6.2.1).
//!
//! Enables multi-turn workflows via session IDs, TTLs, and per-call
//! governance. Session state lives in the tool's context, not the caller's.
//! Each call within a session is individually governed (UCAN validated per
//! call).
//!
//! See ADR-010 in `.docs/adrs/phase-2.md`, section "Stateful tool sessions".
//!
//! # Types
//!
//! - [`ToolSession`] -- A single stateful tool session with TTL and call
//!   tracking.
//! - [`SessionStore`] -- In-memory session storage with TTL-based cleanup.
//!
//! # Functions
//!
//! - [`create_session`] -- Creates a new session and returns its ID.
//! - [`invoke_session`] -- Invokes a tool within an active session with
//!   per-call UCAN governance.
//! - [`cleanup_expired`] -- Removes all sessions past their TTL.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::invoke::has_tool_invoke_capability;
use super::registry::ToolRegistry;
use super::schema::validate_value_against_schema;
use super::{DID, ToolError, ToolId};

/// Default maximum concurrent sessions per calling context (spec section 6.2.1).
///
/// Prevents session exhaustion attacks by bounding the number of active
/// sessions any single calling context can hold simultaneously.
pub const DEFAULT_SESSION_CAP_PER_CALLER: usize = 5;

/// Context identifier type alias.
pub type ContextId = String;
use crate::context::roles::ContextRoleState;
use crate::context::{ContextHandle, ContextState};

// ---------------------------------------------------------------------------
// ToolSession
// ---------------------------------------------------------------------------

/// A stateful tool session enabling multi-turn workflows.
///
/// Session state lives in the tool's context, not the caller's. Each call
/// within a session is individually governed via UCAN capability checks.
/// Sessions have TTLs to prevent resource leaks.
///
/// See spec section 6.2.1 and ADR-010.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSession {
    /// Unique identifier for this session (UUID v4).
    pub session_id: String,
    /// The tool this session is associated with.
    pub tool_id: ToolId,
    /// The context that initiated this session.
    pub source_context: ContextId,
    /// Opaque session state, managed by the tool.
    pub state: serde_json::Value,
    /// Unix timestamp (milliseconds since epoch) when the session was created.
    pub created_at: u64,
    /// Time-to-live for this session. Sessions past their TTL are cleaned up.
    pub ttl: Duration,
    /// Number of invocations made within this session.
    pub call_count: u64,
}

impl ToolSession {
    /// Returns `true` if this session has expired based on the given current
    /// timestamp (milliseconds since epoch).
    #[must_use]
    pub fn is_expired(&self, now_ms: u64) -> bool {
        let ttl_ms = self.ttl.as_millis();
        // Saturating arithmetic to avoid overflow.
        if ttl_ms > u128::from(u64::MAX) {
            return false;
        }
        // ttl_ms is a small positive duration; fits in u64.
        #[allow(clippy::cast_possible_truncation)]
        let ttl_ms_u64 = ttl_ms as u64;
        now_ms.saturating_sub(self.created_at) >= ttl_ms_u64
    }
}

// ---------------------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------------------

/// In-memory session storage for a single SCP context.
///
/// Maps session IDs to their [`ToolSession`] entries. Sessions are cleaned
/// up via [`cleanup_expired`] when they exceed their TTL.
#[derive(Debug, Clone, Default)]
pub struct SessionStore {
    /// Active sessions, keyed by session ID.
    sessions: HashMap<String, ToolSession>,
}

impl SessionStore {
    /// Creates a new empty session store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Returns the session for the given session ID, if it exists.
    #[must_use]
    pub fn get(&self, session_id: &str) -> Option<&ToolSession> {
        self.sessions.get(session_id)
    }

    /// Returns a mutable reference to the session for the given session ID.
    #[must_use]
    pub fn get_mut(&mut self, session_id: &str) -> Option<&mut ToolSession> {
        self.sessions.get_mut(session_id)
    }

    /// Returns the number of active sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Returns `true` if no sessions are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Returns the number of active sessions from a given source context.
    #[must_use]
    pub fn count_by_source(&self, source_context: &str) -> usize {
        self.sessions
            .values()
            .filter(|s| s.source_context == source_context)
            .count()
    }

    /// Inserts a session into the store.
    pub fn insert(&mut self, session: ToolSession) {
        self.sessions.insert(session.session_id.clone(), session);
    }

    /// Removes a session by ID. Returns the removed session if it existed.
    pub fn remove(&mut self, session_id: &str) -> Option<ToolSession> {
        self.sessions.remove(session_id)
    }

    /// Removes expired sessions based on the given current timestamp
    /// (milliseconds since epoch).
    ///
    /// Returns the number of sessions removed.
    pub fn remove_expired(&mut self, now_ms: u64) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, session| !session.is_expired(now_ms));
        before - self.sessions.len()
    }
}

// ---------------------------------------------------------------------------
// create_session
// ---------------------------------------------------------------------------

/// Creates a new stateful tool session.
///
/// Generates a UUID v4 session ID, validates the tool exists in the registry,
/// and stores the session with the given TTL. The initial session state is
/// `serde_json::Value::Null`.
///
/// # Arguments
///
/// * `store` -- The session store to add the session to.
/// * `registry` -- The tool registry to validate the tool exists.
/// * `context` -- The context handle (must be in Active state).
/// * `tool_id` -- The tool to create a session for.
/// * `source_context` -- The context that initiated this session.
/// * `ttl` -- Time-to-live for the session.
///
/// # Returns
///
/// The session ID on success.
///
/// # Errors
///
/// Returns [`ToolError`] if the context is not active or the tool is not
/// found in the registry.
pub async fn create_session(
    store: &mut SessionStore,
    registry: &ToolRegistry,
    context: &ContextHandle,
    tool_id: &ToolId,
    source_context: &ContextId,
    ttl: Duration,
) -> Result<String, ToolError> {
    // Validate context is Active.
    let state = context.state().await;
    if state != ContextState::Active {
        return Err(ToolError::ContextNotActive {
            current_state: state.to_string(),
        });
    }

    // Validate tool exists in the registry.
    if !registry.contains(tool_id) {
        return Err(ToolError::ToolNotFound {
            tool_id: tool_id.clone(),
        });
    }

    // Enforce per-caller session cap (spec section 6.2.1, 9.2.1).
    let current = store.count_by_source(source_context);
    if current >= DEFAULT_SESSION_CAP_PER_CALLER {
        return Err(ToolError::SessionCapExceeded {
            source_context: source_context.clone(),
            current,
            max: DEFAULT_SESSION_CAP_PER_CALLER,
        });
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let now_ms = crate::time::now_millis()?;

    let session = ToolSession {
        session_id: session_id.clone(),
        tool_id: tool_id.clone(),
        source_context: source_context.clone(),
        state: serde_json::Value::Null,
        created_at: now_ms,
        ttl,
        call_count: 0,
    };

    store.insert(session);

    Ok(session_id)
}

// ---------------------------------------------------------------------------
// invoke_session
// ---------------------------------------------------------------------------

/// Invokes a tool within an active session.
///
/// Each call is individually governed: UCAN capability is validated per
/// invocation. The session's call count is incremented and the tool executor
/// may update the session state.
///
/// # Arguments
///
/// * `store` -- The session store containing the session.
/// * `registry` -- The tool registry for schema validation.
/// * `role_state` -- The context's role state for UCAN validation.
/// * `context` -- The context handle (must be in Active state).
/// * `session_id` -- The session to invoke within.
/// * `input` -- The input to pass to the tool.
/// * `invoker_did` -- The DID of the invoker (UCAN validated per call).
/// * `executor` -- The tool execution function. Receives the input and
///   current session state, returns new session state and output.
///
/// # Returns
///
/// The tool output on success.
///
/// # Errors
///
/// Returns [`ToolError`] if:
/// - The context is not active.
/// - The session is not found.
/// - The session has expired.
/// - The invoker does not have the required capability.
/// - Input validation fails.
/// - The tool execution fails.
#[allow(clippy::too_many_arguments)]
pub async fn invoke_session<F, Fut>(
    store: &mut SessionStore,
    registry: &ToolRegistry,
    role_state: &ContextRoleState,
    context: &ContextHandle,
    session_id: &str,
    input: serde_json::Value,
    invoker_did: &DID,
    executor: F,
) -> Result<serde_json::Value, ToolError>
where
    F: FnOnce(serde_json::Value, serde_json::Value) -> Fut,
    Fut: std::future::Future<Output = Result<(serde_json::Value, serde_json::Value), String>>,
{
    // Validate context is Active.
    let ctx_state = context.state().await;
    if ctx_state != ContextState::Active {
        return Err(ToolError::ContextNotActive {
            current_state: ctx_state.to_string(),
        });
    }

    // Look up session.
    let session = store
        .get(session_id)
        .ok_or_else(|| ToolError::SessionNotFound {
            session_id: session_id.to_owned(),
        })?;

    // Check expiry.
    let now_ms = crate::time::now_millis()?;
    if session.is_expired(now_ms) {
        // Remove the expired session.
        store.remove(session_id);
        return Err(ToolError::SessionExpired {
            session_id: session_id.to_owned(),
        });
    }

    let tool_id = session.tool_id.clone();
    let current_state = session.state.clone();

    // Per-call UCAN governance: validate invoker has ToolInvoke capability.
    if !has_tool_invoke_capability(role_state, invoker_did, &tool_id) {
        return Err(ToolError::InvokerNotAuthorized {
            did: invoker_did.to_string(),
            tool_id: tool_id.clone(),
        });
    }

    // Validate input against tool's input schema.
    if let Some(registration) = registry.get(&tool_id) {
        validate_value_against_schema(&input, &registration.schema.input_schema)
            .map_err(|msg| ToolError::InputValidationFailed { message: msg })?;
    }

    // Execute the tool with current session state.
    let (new_state, output) = executor(input, current_state)
        .await
        .map_err(|msg| ToolError::ExecutionFailed { message: msg })?;

    // Update session state and increment call count.
    if let Some(session) = store.get_mut(session_id) {
        session.state = new_state;
        session.call_count = session.call_count.saturating_add(1);
    }

    Ok(output)
}

// ---------------------------------------------------------------------------
// cleanup_expired
// ---------------------------------------------------------------------------

/// Removes all sessions past their TTL from the store.
///
/// This function is designed to be called periodically by the consumer (e.g.,
/// a background task or a timer). It does not spawn its own task.
///
/// Returns the number of sessions removed.
pub fn cleanup_expired(store: &mut SessionStore, now_ms: u64) -> usize {
    store.remove_expired(now_ms)
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
    use crate::context::tools::registry::{ToolRegistration, ToolSchema, register_tool};

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

    /// Creates a `ContextRoleState` with a creator that has admin capabilities.
    fn test_role_state(creator_did: &str) -> ContextRoleState {
        ContextRoleState::new("ctx-test", creator_did, test_ceiling(), vec![]).unwrap()
    }

    /// Creates a `ContextRoleState` with a member that has no tool invoke
    /// capability.
    fn test_role_state_with_no_invoke_member(
        creator_did: &str,
        member_did: &str,
    ) -> ContextRoleState {
        let mut state = test_role_state(creator_did);
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

    /// Creates an active context handle.
    async fn active_context() -> ContextHandle {
        let handle = ContextHandle::new("ctx-session-test".to_owned(), ContextParams::default());
        handle.transition_to(&ContextState::Active).await.unwrap();
        handle
    }

    /// Registers a test tool and returns the registry.
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
            registered_at: 0,
            signature: Vec::new(),
        };
        register_tool(&mut registry, role_state, registration, registrant_did).unwrap();
        registry
    }

    /// Simple executor that adds two numbers and preserves session state.
    async fn add_executor(
        input: serde_json::Value,
        session_state: serde_json::Value,
    ) -> Result<(serde_json::Value, serde_json::Value), String> {
        let a = input
            .get("a")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| "missing field 'a'".to_owned())?;
        let b = input
            .get("b")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| "missing field 'b'".to_owned())?;
        let result = a + b;

        // Accumulate results in session state.
        let mut history = match session_state {
            serde_json::Value::Array(arr) => arr,
            serde_json::Value::Null => Vec::new(),
            other => vec![other],
        };
        history.push(serde_json::json!({"result": result}));

        let new_state = serde_json::Value::Array(history);
        let output = serde_json::json!({"result": result});
        Ok((new_state, output))
    }

    // -----------------------------------------------------------------------
    // ToolSession::is_expired
    // -----------------------------------------------------------------------

    #[test]
    fn session_not_expired_within_ttl() {
        let session = ToolSession {
            session_id: "sess-1".to_owned(),
            tool_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Duration::from_secs(60),
            call_count: 0,
        };
        // 30 seconds later -- should not be expired.
        assert!(!session.is_expired(31_000));
    }

    #[test]
    fn session_expired_past_ttl() {
        let session = ToolSession {
            session_id: "sess-1".to_owned(),
            tool_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Duration::from_secs(60),
            call_count: 0,
        };
        // 61 seconds later -- should be expired.
        assert!(session.is_expired(62_000));
    }

    #[test]
    fn session_expired_at_exact_ttl_boundary() {
        let session = ToolSession {
            session_id: "sess-1".to_owned(),
            tool_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Duration::from_secs(60),
            call_count: 0,
        };
        // Exactly at TTL boundary -- should be expired (>= check).
        assert!(session.is_expired(61_000));
    }

    // -----------------------------------------------------------------------
    // SessionStore
    // -----------------------------------------------------------------------

    #[test]
    fn session_store_starts_empty() {
        let store = SessionStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn session_store_get_returns_none_for_missing() {
        let store = SessionStore::new();
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn session_store_remove_expired_removes_only_expired() {
        let mut store = SessionStore::new();

        // Session 1: created at 1000, TTL 60s -- expires at 61000.
        store.insert(ToolSession {
            session_id: "sess-active".to_owned(),
            tool_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Duration::from_secs(60),
            call_count: 0,
        });

        // Session 2: created at 1000, TTL 10s -- expires at 11000.
        store.insert(ToolSession {
            session_id: "sess-expired".to_owned(),
            tool_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Duration::from_secs(10),
            call_count: 0,
        });

        assert_eq!(store.len(), 2);

        // At 15000ms: sess-expired (11000) is expired, sess-active (61000) is not.
        let removed = store.remove_expired(15_000);
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 1);
        assert!(store.get("sess-active").is_some());
        assert!(store.get("sess-expired").is_none());
    }

    // -----------------------------------------------------------------------
    // create_session: returns valid session ID
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_session_returns_valid_session_id() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let mut store = SessionStore::new();

        let result = create_session(
            &mut store,
            &registry,
            &context,
            &"calculator".to_owned(),
            &"ctx-source".to_owned(),
            Duration::from_secs(300),
        )
        .await;

        assert!(result.is_ok(), "create_session should succeed: {result:?}");
        let session_id = result.unwrap();

        // UUID v4 format: 8-4-4-4-12 hex digits.
        assert_eq!(session_id.len(), 36);
        assert!(session_id.contains('-'));

        // Verify session is stored.
        assert_eq!(store.len(), 1);
        let session = store.get(&session_id).unwrap();
        assert_eq!(session.tool_id, "calculator");
        assert_eq!(session.source_context, "ctx-source");
        assert_eq!(session.call_count, 0);
        assert_eq!(session.ttl, Duration::from_secs(300));
        assert!(session.state.is_null());
    }

    #[tokio::test]
    async fn create_session_rejects_when_context_not_active() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = ContextHandle::new("ctx-creating".to_owned(), ContextParams::default());
        let mut store = SessionStore::new();

        let result = create_session(
            &mut store,
            &registry,
            &context,
            &"calculator".to_owned(),
            &"ctx-source".to_owned(),
            Duration::from_secs(300),
        )
        .await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ToolError::ContextNotActive { .. }),
            "expected ContextNotActive"
        );
    }

    #[tokio::test]
    async fn create_session_rejects_unknown_tool() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let mut store = SessionStore::new();

        let result = create_session(
            &mut store,
            &registry,
            &context,
            &"nonexistent-tool".to_owned(),
            &"ctx-source".to_owned(),
            Duration::from_secs(300),
        )
        .await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ToolError::ToolNotFound { .. }),
            "expected ToolNotFound"
        );
    }

    // -----------------------------------------------------------------------
    // create_session: per-caller session cap (spec section 6.2.1)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_session_rejects_when_caller_cap_exceeded() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let mut store = SessionStore::new();
        let source_ctx = "ctx-source".to_owned();

        // Fill up to the cap (DEFAULT_SESSION_CAP_PER_CALLER = 5).
        for _ in 0..DEFAULT_SESSION_CAP_PER_CALLER {
            let result = create_session(
                &mut store,
                &registry,
                &context,
                &"calculator".to_owned(),
                &source_ctx,
                Duration::from_secs(300),
            )
            .await;
            assert!(
                result.is_ok(),
                "sessions under cap should succeed: {result:?}"
            );
        }

        assert_eq!(store.count_by_source(&source_ctx), 5);

        // The next session from the same caller should fail.
        let result = create_session(
            &mut store,
            &registry,
            &context,
            &"calculator".to_owned(),
            &source_ctx,
            Duration::from_secs(300),
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ToolError::SessionCapExceeded {
                    current: 5,
                    max: 5,
                    ..
                }
            ),
            "expected SessionCapExceeded, got {err:?}"
        );
    }

    #[tokio::test]
    async fn create_session_allows_different_callers_independently() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let mut store = SessionStore::new();

        // Fill caller A to the cap.
        for _ in 0..DEFAULT_SESSION_CAP_PER_CALLER {
            create_session(
                &mut store,
                &registry,
                &context,
                &"calculator".to_owned(),
                &"ctx-caller-a".to_owned(),
                Duration::from_secs(300),
            )
            .await
            .unwrap();
        }

        // Caller B should still be able to create sessions.
        let result = create_session(
            &mut store,
            &registry,
            &context,
            &"calculator".to_owned(),
            &"ctx-caller-b".to_owned(),
            Duration::from_secs(300),
        )
        .await;

        assert!(
            result.is_ok(),
            "different caller should not be affected by another caller's cap: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_session: expired session returns error
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_session_on_expired_session_returns_error() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let mut store = SessionStore::new();

        // Insert a session that is already expired (TTL = 0).
        store.insert(ToolSession {
            session_id: "sess-expired".to_owned(),
            tool_id: "calculator".to_owned(),
            source_context: "ctx-source".to_owned(),
            state: serde_json::Value::Null,
            created_at: 0,
            ttl: Duration::from_secs(0),
            call_count: 0,
        });

        let result = invoke_session(
            &mut store,
            &registry,
            &role_state,
            &context,
            "sess-expired",
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            add_executor,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ToolError::SessionExpired { .. }),
            "expected SessionExpired, got {err:?}"
        );

        // Expired session should be removed from the store.
        assert!(store.get("sess-expired").is_none());
    }

    // -----------------------------------------------------------------------
    // TTL cleanup removes expired sessions
    // -----------------------------------------------------------------------

    #[test]
    fn ttl_cleanup_removes_expired_sessions() {
        let mut store = SessionStore::new();

        // Insert 3 sessions with different TTLs.
        store.insert(ToolSession {
            session_id: "sess-1".to_owned(),
            tool_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Duration::from_secs(10), // Expires at 11000ms
            call_count: 0,
        });
        store.insert(ToolSession {
            session_id: "sess-2".to_owned(),
            tool_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Duration::from_secs(30), // Expires at 31000ms
            call_count: 0,
        });
        store.insert(ToolSession {
            session_id: "sess-3".to_owned(),
            tool_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Duration::from_secs(120), // Expires at 121000ms
            call_count: 0,
        });

        assert_eq!(store.len(), 3);

        // At 20000ms: only sess-1 (11000) is expired.
        let removed = cleanup_expired(&mut store, 20_000);
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 2);

        // At 50000ms: sess-2 (31000) is now also expired.
        let removed = cleanup_expired(&mut store, 50_000);
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 1);
        assert!(store.get("sess-3").is_some());

        // At 200000ms: sess-3 (121000) is now also expired.
        let removed = cleanup_expired(&mut store, 200_000);
        assert_eq!(removed, 1);
        assert!(store.is_empty());
    }

    // -----------------------------------------------------------------------
    // Each call in session is individually governed (UCAN validated per call)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_session_validates_ucan_per_call() {
        let creator_did = "did:dht:z6MkCreator";
        let member_did = "did:dht:z6MkMember";
        let role_state = test_role_state_with_no_invoke_member(creator_did, member_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let mut store = SessionStore::new();

        // Create session (using the store directly since create_session
        // doesn't check invoker capabilities -- that's per-call).
        let session_id = create_session(
            &mut store,
            &registry,
            &context,
            &"calculator".to_owned(),
            &"ctx-source".to_owned(),
            Duration::from_secs(300),
        )
        .await
        .unwrap();

        // First call by creator (has ToolInvokeAll) -- should succeed.
        let result = invoke_session(
            &mut store,
            &registry,
            &role_state,
            &context,
            &session_id,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            add_executor,
        )
        .await;
        assert!(
            result.is_ok(),
            "creator invocation should succeed: {result:?}"
        );
        assert_eq!(result.unwrap(), serde_json::json!({"result": 3.0}));

        // Second call by member (no ToolInvoke capability) -- should fail.
        let result = invoke_session(
            &mut store,
            &registry,
            &role_state,
            &context,
            &session_id,
            serde_json::json!({"a": 3, "b": 4}),
            &DID::from(member_did),
            add_executor,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ToolError::InvokerNotAuthorized { .. }),
            "expected InvokerNotAuthorized, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_session: session not found
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_session_returns_error_for_unknown_session() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let mut store = SessionStore::new();

        let result = invoke_session(
            &mut store,
            &registry,
            &role_state,
            &context,
            "nonexistent-session",
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            add_executor,
        )
        .await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ToolError::SessionNotFound { .. }),
            "expected SessionNotFound"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_session: happy path with state accumulation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_session_increments_call_count_and_updates_state() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let mut store = SessionStore::new();

        let session_id = create_session(
            &mut store,
            &registry,
            &context,
            &"calculator".to_owned(),
            &"ctx-source".to_owned(),
            Duration::from_secs(300),
        )
        .await
        .unwrap();

        // First call.
        let output = invoke_session(
            &mut store,
            &registry,
            &role_state,
            &context,
            &session_id,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            add_executor,
        )
        .await
        .unwrap();
        assert_eq!(output, serde_json::json!({"result": 3.0}));

        let session = store.get(&session_id).unwrap();
        assert_eq!(session.call_count, 1);
        assert!(session.state.is_array());

        // Second call.
        let output = invoke_session(
            &mut store,
            &registry,
            &role_state,
            &context,
            &session_id,
            serde_json::json!({"a": 10, "b": 20}),
            &DID::from(creator_did),
            add_executor,
        )
        .await
        .unwrap();
        assert_eq!(output, serde_json::json!({"result": 30.0}));

        let session = store.get(&session_id).unwrap();
        assert_eq!(session.call_count, 2);
        // Session state should have two entries.
        assert_eq!(session.state.as_array().unwrap().len(), 2);
    }

    // -----------------------------------------------------------------------
    // invoke_session: context not active
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_session_rejects_when_context_not_active() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = ContextHandle::new("ctx-creating".to_owned(), ContextParams::default());
        let mut store = SessionStore::new();

        // Insert a session directly.
        store.insert(ToolSession {
            session_id: "sess-1".to_owned(),
            tool_id: "calculator".to_owned(),
            source_context: "ctx-source".to_owned(),
            state: serde_json::Value::Null,
            created_at: crate::time::now_millis().unwrap(),
            ttl: Duration::from_secs(300),
            call_count: 0,
        });

        let result = invoke_session(
            &mut store,
            &registry,
            &role_state,
            &context,
            "sess-1",
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            add_executor,
        )
        .await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ToolError::ContextNotActive { .. }),
            "expected ContextNotActive"
        );
    }

    // -----------------------------------------------------------------------
    // ToolSession serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn tool_session_serialization_roundtrip() {
        let session = ToolSession {
            session_id: "sess-abc".to_owned(),
            tool_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::json!({"key": "value"}),
            created_at: 1_000_000,
            ttl: Duration::from_secs(600),
            call_count: 42,
        };
        let json = serde_json::to_string(&session).unwrap();
        let deserialized: ToolSession = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.session_id, "sess-abc");
        assert_eq!(deserialized.tool_id, "tool-1");
        assert_eq!(deserialized.source_context, "ctx-src");
        assert_eq!(deserialized.call_count, 42);
    }

    // -----------------------------------------------------------------------
    // invoke_session: execution failure propagates
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_session_propagates_execution_failure() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let mut store = SessionStore::new();

        let session_id = create_session(
            &mut store,
            &registry,
            &context,
            &"calculator".to_owned(),
            &"ctx-source".to_owned(),
            Duration::from_secs(300),
        )
        .await
        .unwrap();

        // Executor that always fails.
        let failing_executor = |_input: serde_json::Value, _state: serde_json::Value| async {
            Err::<(serde_json::Value, serde_json::Value), String>("computation exploded".to_owned())
        };

        let result = invoke_session(
            &mut store,
            &registry,
            &role_state,
            &context,
            &session_id,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            failing_executor,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ToolError::ExecutionFailed { .. }),
            "expected ExecutionFailed, got {err:?}"
        );
        assert!(err.to_string().contains("computation exploded"));
    }
}
