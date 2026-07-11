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
//! - [`OutletSession`] -- A single stateful tool session with TTL and call
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

use scp_clock::Clock;

use super::invoke::has_outlet_invocation_capability;
use scp_did::DID;
use scp_protocol::context::outlets::registry::OutletRegistry;
use scp_protocol::context::outlets::schema::validate_value_against_schema;
use scp_protocol::context::outlets::{OutletError, OutletId, OutletKind};

/// Default maximum concurrent sessions per calling context (spec §6.2.1, ADR-043).
///
/// Prevents session exhaustion attacks by bounding the number of active
/// sessions any single calling context can hold simultaneously. Context-
/// configurable via `ContextParams::session_cap`.
pub const DEFAULT_SESSION_CAP_PER_CALLER: u32 = 1000;

/// Context identifier type alias.
pub type ContextId = String;
use crate::context::ContextHandle;
use scp_protocol::context::ContextState;
use scp_protocol::context::roles::ContextRoleState;

// ---------------------------------------------------------------------------
// OutletSession
// ---------------------------------------------------------------------------

/// A stateful tool session enabling multi-turn workflows.
///
/// Session state lives in the tool's context, not the caller's. Each call
/// within a session is individually governed via UCAN capability checks.
/// Sessions have an optional TTL. Sessions without a TTL persist for
/// the lifetime of the context (spec section 6.2.1).
///
/// See spec section 6.2.1 and ADR-010.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutletSession {
    /// Unique identifier for this session (UUID v4).
    pub session_id: String,
    /// The tool this session is associated with.
    pub outlet_id: OutletId,
    /// The context that initiated this session.
    pub source_context: ContextId,
    /// Opaque session state, managed by the tool.
    pub state: serde_json::Value,
    /// Unix timestamp (milliseconds since epoch) when the session was created.
    pub created_at: u64,
    /// Optional time-to-live for this session. `None` means the session
    /// persists for the lifetime of the context and is never expired by
    /// TTL cleanup. `Some(duration)` means the session expires after the
    /// given duration.
    pub ttl: Option<Duration>,
    /// Number of invocations made within this session.
    pub call_count: u64,
}

impl OutletSession {
    /// Returns `true` if this session has expired based on the given current
    /// timestamp (milliseconds since epoch).
    ///
    /// Sessions with `ttl: None` never expire (they persist for the
    /// lifetime of the context, per spec section 6.2.1).
    #[must_use]
    pub fn is_expired(&self, now_ms: u64) -> bool {
        let Some(ttl) = self.ttl else {
            return false;
        };
        let ttl_ms = ttl.as_millis();
        // Saturating arithmetic to avoid overflow.
        if ttl_ms > u128::from(u64::MAX) {
            return false;
        }
        // ttl_ms is a small positive duration; fits in u64.
        let ttl_ms_u64 = u64::try_from(ttl_ms).unwrap_or(u64::MAX);
        now_ms.saturating_sub(self.created_at) >= ttl_ms_u64
    }
}

// ---------------------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------------------

/// In-memory session storage for a single SCP context.
///
/// Maps session IDs to their [`OutletSession`] entries. Sessions are cleaned
/// up via [`cleanup_expired`] when they exceed their TTL.
#[derive(Debug, Clone, Default)]
pub struct SessionStore {
    /// Active sessions, keyed by session ID.
    sessions: HashMap<String, OutletSession>,
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
    pub fn get(&self, session_id: &str) -> Option<&OutletSession> {
        self.sessions.get(session_id)
    }

    /// Returns a mutable reference to the session for the given session ID.
    #[must_use]
    pub fn get_mut(&mut self, session_id: &str) -> Option<&mut OutletSession> {
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
    pub fn insert(&mut self, session: OutletSession) {
        self.sessions.insert(session.session_id.clone(), session);
    }

    /// Removes a session by ID. Returns the removed session if it existed.
    pub fn remove(&mut self, session_id: &str) -> Option<OutletSession> {
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
/// * `outlet_id` -- The tool to create a session for.
/// * `source_context` -- The context that initiated this session.
/// * `ttl` -- Optional time-to-live for the session. `None` means the
///   session persists for the lifetime of the context.
///
/// # Returns
///
/// The session ID on success.
///
/// # Errors
///
/// Returns [`OutletError`] if the context is not active or the tool is not
/// found in the registry.
// ADR-049 §Decision 12: `state` is now a synchronous lock-free ArcSwap load,
// so this body has no `.await`. It calls no async provider trait; `async` is
// retained purely for API symmetry with the genuinely-async `invoke_session`
// (which awaits the tool executor) and as the stable ContextManager tool API
// contract — not for any pending provider await.
#[allow(
    clippy::unused_async,
    reason = "kept async for API symmetry with the async invoke_session and the stable tool API contract; body has no await and calls no async provider"
)]
pub async fn create_session(
    store: &mut SessionStore,
    registry: &OutletRegistry,
    context: &ContextHandle,
    outlet_id: &OutletId,
    source_context: &ContextId,
    ttl: Option<Duration>,
    clock: &dyn Clock,
) -> Result<String, OutletError> {
    // Validate context is Active.
    let state = context.state();
    if state != ContextState::Active {
        return Err(OutletError::ContextNotActive {
            current_state: state.to_string(),
        });
    }

    // Validate tool exists in the registry.
    if !registry.contains(outlet_id) {
        return Err(OutletError::OutletNotFound {
            outlet_id: outlet_id.clone(),
        });
    }

    // Enforce per-caller session cap (spec §6.2.1, §9.2.1, ADR-043).
    // Use context-configured cap, falling back to DEFAULT_SESSION_CAP_PER_CALLER.
    let cap = context
        .params()
        .session_cap
        .unwrap_or(DEFAULT_SESSION_CAP_PER_CALLER);
    let current = u32::try_from(store.count_by_source(source_context)).unwrap_or(u32::MAX);
    if current >= cap {
        return Err(OutletError::SessionCapExceeded {
            source_context: source_context.clone(),
            current,
            max: cap,
        });
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let now_ms = clock.now_millis();

    let session = OutletSession {
        session_id: session_id.clone(),
        outlet_id: outlet_id.clone(),
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
/// Returns [`OutletError`] if:
/// - The context is not active.
/// - The session is not found.
/// - The session has expired.
/// - The invoker does not have the required capability.
/// - Input validation fails.
/// - The tool execution fails.
#[allow(clippy::too_many_arguments)]
pub async fn invoke_session<F, Fut>(
    store: &mut SessionStore,
    registry: &OutletRegistry,
    role_state: &ContextRoleState,
    context: &ContextHandle,
    session_id: &str,
    input: serde_json::Value,
    invoker_did: &DID,
    executor: F,
    clock: &dyn Clock,
) -> Result<serde_json::Value, OutletError>
where
    F: FnOnce(serde_json::Value, serde_json::Value) -> Fut,
    Fut: std::future::Future<Output = Result<(serde_json::Value, serde_json::Value), String>>,
{
    // Validate context is Active.
    let ctx_state = context.state();
    if ctx_state != ContextState::Active {
        return Err(OutletError::ContextNotActive {
            current_state: ctx_state.to_string(),
        });
    }

    // Look up session.
    let session = store
        .get(session_id)
        .ok_or_else(|| OutletError::SessionNotFound {
            session_id: session_id.to_owned(),
        })?;

    // Check expiry.
    let now_ms = clock.now_millis();
    if session.is_expired(now_ms) {
        // Remove the expired session.
        store.remove(session_id);
        return Err(OutletError::SessionExpired {
            session_id: session_id.to_owned(),
        });
    }

    let outlet_id = session.outlet_id.clone();
    let current_state = session.state.clone();

    // Per-call governance: validate invoker holds the kind-appropriate split
    // capability. Query outlets require OutletQuery(id)/OutletQueryAll, Action
    // outlets require OutletCall(id)/OutletCallAll (SCP-OUT-014, §5.4.2). The
    // outlet's registered kind is the authority; an outlet absent from the
    // registry defaults to the Action stem (fail-closed toward the call cap).
    let outlet_kind = registry
        .get(&outlet_id)
        .map_or(OutletKind::Action, |registration| registration.kind);
    if !has_outlet_invocation_capability(role_state, invoker_did, &outlet_id, outlet_kind) {
        return Err(OutletError::InvokerNotAuthorized {
            did: invoker_did.to_string(),
            outlet_id: outlet_id.clone(),
        });
    }

    // Validate input against tool's input schema.
    if let Some(registration) = registry.get(&outlet_id) {
        validate_value_against_schema(&input, &registration.schema.input_schema)
            .map_err(|msg| OutletError::InputValidationFailed { message: msg })?;
    }

    // Execute the tool with current session state.
    let (new_state, output) = executor(input, current_state)
        .await
        .map_err(|msg| OutletError::ExecutionFailed { message: msg })?;

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
    use scp_protocol::context::ContextParams;
    use scp_protocol::context::outlets::registry::{
        OutletRegistration, OutletSchema, register_outlet,
    };
    use scp_protocol::context::roles::{Capability, CapabilityCeiling, ContextRoleState};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

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

    /// Creates a `ContextRoleState` with a creator that has admin capabilities.
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
    fn active_context() -> ContextHandle {
        let handle = ContextHandle::new("ctx-session-test".to_owned(), ContextParams::default());
        handle.transition_to(&ContextState::Active).unwrap();
        handle
    }

    /// Registers a test tool and returns the registry.
    fn setup_registry_with_outlet(
        role_state: &ContextRoleState,
        registrant_did: &str,
    ) -> OutletRegistry {
        let mut registry = OutletRegistry::new();
        let registration = OutletRegistration {
            outlet_id: "calculator".to_owned(),
            kind: scp_protocol::context::outlets::OutletKind::default(),
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

    /// Registers a `calculator` outlet of the given [`OutletKind`] (SCP-OUT-014)
    /// and returns the registry. Mirrors [`setup_registry_with_outlet`] but lets
    /// the caller pick Query vs Action so the split-capability gate can be
    /// exercised end-to-end through the session path.
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
    // OutletSession::is_expired
    // -----------------------------------------------------------------------

    #[test]
    fn session_not_expired_within_ttl() {
        let session = OutletSession {
            session_id: "sess-1".to_owned(),
            outlet_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Some(Duration::from_mins(1)),
            call_count: 0,
        };
        // 30 seconds later -- should not be expired.
        assert!(!session.is_expired(31_000));
    }

    #[test]
    fn session_expired_past_ttl() {
        let session = OutletSession {
            session_id: "sess-1".to_owned(),
            outlet_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Some(Duration::from_mins(1)),
            call_count: 0,
        };
        // 61 seconds later -- should be expired.
        assert!(session.is_expired(62_000));
    }

    #[test]
    fn session_expired_at_exact_ttl_boundary() {
        let session = OutletSession {
            session_id: "sess-1".to_owned(),
            outlet_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Some(Duration::from_mins(1)),
            call_count: 0,
        };
        // Exactly at TTL boundary -- should be expired (>= check).
        assert!(session.is_expired(61_000));
    }

    #[test]
    fn session_with_none_ttl_never_expires() {
        let session = OutletSession {
            session_id: "sess-1".to_owned(),
            outlet_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: None,
            call_count: 0,
        };
        // Even far in the future -- should never expire.
        assert!(!session.is_expired(u64::MAX));
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
        store.insert(OutletSession {
            session_id: "sess-active".to_owned(),
            outlet_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Some(Duration::from_mins(1)),
            call_count: 0,
        });

        // Session 2: created at 1000, TTL 10s -- expires at 11000.
        store.insert(OutletSession {
            session_id: "sess-expired".to_owned(),
            outlet_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Some(Duration::from_secs(10)),
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
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();
        let mut store = SessionStore::new();

        let result = create_session(
            &mut store,
            &registry,
            &context,
            &"calculator".to_owned(),
            &"ctx-source".to_owned(),
            Some(Duration::from_mins(5)),
            &scp_clock::SystemClock,
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
        assert_eq!(session.outlet_id, "calculator");
        assert_eq!(session.source_context, "ctx-source");
        assert_eq!(session.call_count, 0);
        assert_eq!(session.ttl, Some(Duration::from_mins(5)));
        assert!(session.state.is_null());
    }

    #[tokio::test]
    async fn create_session_rejects_when_context_not_active() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = ContextHandle::new("ctx-creating".to_owned(), ContextParams::default());
        let mut store = SessionStore::new();

        let result = create_session(
            &mut store,
            &registry,
            &context,
            &"calculator".to_owned(),
            &"ctx-source".to_owned(),
            Some(Duration::from_mins(5)),
            &scp_clock::SystemClock,
        )
        .await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), OutletError::ContextNotActive { .. }),
            "expected ContextNotActive"
        );
    }

    #[tokio::test]
    async fn create_session_rejects_unknown_tool() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();
        let mut store = SessionStore::new();

        let result = create_session(
            &mut store,
            &registry,
            &context,
            &"nonexistent-tool".to_owned(),
            &"ctx-source".to_owned(),
            Some(Duration::from_mins(5)),
            &scp_clock::SystemClock,
        )
        .await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), OutletError::OutletNotFound { .. }),
            "expected OutletNotFound"
        );
    }

    // -----------------------------------------------------------------------
    // create_session: per-caller session cap (spec section 6.2.1)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_session_rejects_when_caller_cap_exceeded() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        // Use a context with session_cap = Some(5) for a manageable test.
        let params = ContextParams {
            session_cap: Some(5),
            ..ContextParams::default()
        };
        let context = ContextHandle::new("ctx-session-test".to_owned(), params);
        context.transition_to(&ContextState::Active).unwrap();
        let mut store = SessionStore::new();
        let source_ctx = "ctx-source".to_owned();

        // Fill up to the configured cap (5).
        for _ in 0..5u32 {
            let result = create_session(
                &mut store,
                &registry,
                &context,
                &"calculator".to_owned(),
                &source_ctx,
                Some(Duration::from_mins(5)),
                &scp_clock::SystemClock,
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
            Some(Duration::from_mins(5)),
            &scp_clock::SystemClock,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                OutletError::SessionCapExceeded {
                    current: 5,
                    max: 5,
                    ..
                }
            ),
            "expected SessionCapExceeded, got {err:?}"
        );
    }

    #[tokio::test]
    async fn create_session_default_cap_is_1000() {
        // ContextParams { session_cap: None } should resolve to DEFAULT_SESSION_CAP_PER_CALLER (1000).
        assert_eq!(DEFAULT_SESSION_CAP_PER_CALLER, 1000);
        let context = active_context();
        assert!(context.params().session_cap.is_none());
    }

    #[tokio::test]
    async fn create_session_allows_different_callers_independently() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        // Use session_cap = Some(3) for a manageable test.
        let params = ContextParams {
            session_cap: Some(3),
            ..ContextParams::default()
        };
        let context = ContextHandle::new("ctx-session-test".to_owned(), params);
        context.transition_to(&ContextState::Active).unwrap();
        let mut store = SessionStore::new();

        // Fill caller A to the cap.
        for _ in 0..3u32 {
            create_session(
                &mut store,
                &registry,
                &context,
                &"calculator".to_owned(),
                &"ctx-caller-a".to_owned(),
                Some(Duration::from_mins(5)),
                &scp_clock::SystemClock,
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
            Some(Duration::from_mins(5)),
            &scp_clock::SystemClock,
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
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();
        let mut store = SessionStore::new();

        // Insert a session that is already expired (TTL = 0).
        store.insert(OutletSession {
            session_id: "sess-expired".to_owned(),
            outlet_id: "calculator".to_owned(),
            source_context: "ctx-source".to_owned(),
            state: serde_json::Value::Null,
            created_at: 0,
            ttl: Some(Duration::from_secs(0)),
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
            &scp_clock::SystemClock,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, OutletError::SessionExpired { .. }),
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
        store.insert(OutletSession {
            session_id: "sess-1".to_owned(),
            outlet_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Some(Duration::from_secs(10)), // Expires at 11000ms
            call_count: 0,
        });
        store.insert(OutletSession {
            session_id: "sess-2".to_owned(),
            outlet_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Some(Duration::from_secs(30)), // Expires at 31000ms
            call_count: 0,
        });
        store.insert(OutletSession {
            session_id: "sess-3".to_owned(),
            outlet_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::Value::Null,
            created_at: 1000,
            ttl: Some(Duration::from_mins(2)), // Expires at 121000ms
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
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();
        let mut store = SessionStore::new();

        // Create session (using the store directly since create_session
        // doesn't check invoker capabilities -- that's per-call).
        let session_id = create_session(
            &mut store,
            &registry,
            &context,
            &"calculator".to_owned(),
            &"ctx-source".to_owned(),
            Some(Duration::from_mins(5)),
            &scp_clock::SystemClock,
        )
        .await
        .unwrap();

        // First call by creator (has OutletCallAll) -- should succeed.
        let result = invoke_session(
            &mut store,
            &registry,
            &role_state,
            &context,
            &session_id,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            add_executor,
            &scp_clock::SystemClock,
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
            &scp_clock::SystemClock,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, OutletError::InvokerNotAuthorized { .. }),
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
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();
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
            &scp_clock::SystemClock,
        )
        .await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), OutletError::SessionNotFound { .. }),
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
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();
        let mut store = SessionStore::new();

        let session_id = create_session(
            &mut store,
            &registry,
            &context,
            &"calculator".to_owned(),
            &"ctx-source".to_owned(),
            Some(Duration::from_mins(5)),
            &scp_clock::SystemClock,
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
            &scp_clock::SystemClock,
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
            &scp_clock::SystemClock,
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
    // invoke_session: end-to-end split-capability gate (SCP-OUT-014, §5.4.2).
    // Proves the session path honours the outlet's registered kind: a Query
    // outlet is DENIED to a member holding only OutletCall and ALLOWED once the
    // member holds OutletQuery. Guards the wiring at session.rs:363.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_query_session_denied_with_call_cap_allowed_with_query_cap() {
        let creator = "did:dht:z6MkCreator";
        let member = "did:dht:z6MkMember";

        // Creator (admin) registers a QUERY-kind outlet.
        let mut role_state = test_role_state(creator);
        role_state.members.insert(member.to_owned());
        let registry = setup_registry_with_kind(&role_state, creator, OutletKind::Query);
        let context = active_context();
        let mut store = SessionStore::new();

        let session_id = create_session(
            &mut store,
            &registry,
            &context,
            &"calculator".to_owned(),
            &"ctx-source".to_owned(),
            Some(Duration::from_mins(5)),
            &scp_clock::SystemClock,
        )
        .await
        .unwrap();

        // Member holds ONLY the Action-class OutletCall grant → DENIED, because
        // the outlet is registered as Query and the two stems are independent.
        role_state.member_capabilities.insert(
            member.to_owned(),
            std::iter::once(Capability::OutletCall("calculator".to_owned())).collect(),
        );
        let denied = invoke_session(
            &mut store,
            &registry,
            &role_state,
            &context,
            &session_id,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member),
            add_executor,
            &scp_clock::SystemClock,
        )
        .await;
        assert!(
            matches!(
                denied.unwrap_err(),
                OutletError::InvokerNotAuthorized { .. }
            ),
            "Query session must be denied to a member holding only OutletCall"
        );

        // Grant the Query-class capability → ALLOWED.
        role_state
            .member_capabilities
            .get_mut(member)
            .unwrap()
            .insert(Capability::OutletQuery("calculator".to_owned()));
        let allowed = invoke_session(
            &mut store,
            &registry,
            &role_state,
            &context,
            &session_id,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member),
            add_executor,
            &scp_clock::SystemClock,
        )
        .await;
        assert!(
            allowed.is_ok(),
            "Query session must be allowed once the member holds OutletQuery: {:?}",
            allowed.err()
        );
    }

    // -----------------------------------------------------------------------
    // invoke_session: context not active
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_session_rejects_when_context_not_active() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = ContextHandle::new("ctx-creating".to_owned(), ContextParams::default());
        let mut store = SessionStore::new();

        // Insert a session directly.
        store.insert(OutletSession {
            session_id: "sess-1".to_owned(),
            outlet_id: "calculator".to_owned(),
            source_context: "ctx-source".to_owned(),
            state: serde_json::Value::Null,
            created_at: scp_clock::SystemClock.now_millis(),
            ttl: Some(Duration::from_mins(5)),
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
            &scp_clock::SystemClock,
        )
        .await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), OutletError::ContextNotActive { .. }),
            "expected ContextNotActive"
        );
    }

    // -----------------------------------------------------------------------
    // OutletSession serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn outlet_session_serialization_roundtrip() {
        let session = OutletSession {
            session_id: "sess-abc".to_owned(),
            outlet_id: "tool-1".to_owned(),
            source_context: "ctx-src".to_owned(),
            state: serde_json::json!({"key": "value"}),
            created_at: 1_000_000,
            ttl: Some(Duration::from_mins(10)),
            call_count: 42,
        };
        let json = serde_json::to_string(&session).unwrap();
        let deserialized: OutletSession = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.session_id, "sess-abc");
        assert_eq!(deserialized.outlet_id, "tool-1");
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
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let context = active_context();
        let mut store = SessionStore::new();

        let session_id = create_session(
            &mut store,
            &registry,
            &context,
            &"calculator".to_owned(),
            &"ctx-source".to_owned(),
            Some(Duration::from_mins(5)),
            &scp_clock::SystemClock,
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
            &scp_clock::SystemClock,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, OutletError::ExecutionFailed { .. }),
            "expected ExecutionFailed, got {err:?}"
        );
        assert!(err.to_string().contains("computation exploded"));
    }
}
