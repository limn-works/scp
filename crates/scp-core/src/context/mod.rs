//! Context lifecycle types for SCP.
//!
//! This module implements the context lifecycle as a five-state finite state
//! machine: `Creating -> Active -> Closing -> Closed`, with `Expired` as a
//! terminal state reachable from `Active` when TTL elapses. See ADR-008 in
//! `.docs/adrs/phase-2.md`.
//!
//! # Types
//!
//! - [`ContextState`] -- The five lifecycle states.
//! - [`ContextHandle`] -- Thread-safe handle to a context, holding state and
//!   parameters. `Send + Sync` via interior `Arc<RwLock<_>>`.
//! - [`ContextError`] -- Error type for context operations.
//! - [`ContextParams`] -- Full context configuration (re-exported from
//!   [`params`]).
//!
//! # State Machine
//!
//! The [`state_machine::transition`] function validates state transitions and
//! returns the new state or an error. It is pure -- no side effects. The
//! Context Manager (SCP-019/020) is responsible for executing side effects.
//!
//! # Concurrency
//!
//! All public handle types are `Send + Sync`. Individual operations on shared
//! handles are serialized internally via `tokio::sync::RwLock`. See
//! `.docs/standards/sdk-common.md` Concurrency Model.

pub mod builder;
pub mod manager;
pub mod params;
pub mod roles;
pub mod state_machine;
pub mod templates;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

// Re-export all parameter types for convenience.
pub use params::{
    Capability, CeilingPolicy, ContextMode, ContextParams, GovernanceModel, MemoryScope,
    PromotionPolicy, RoleDefinition, TemplateId, ToolRegistration,
};
pub use state_machine::transition;

// Re-export template types for convenience.
pub use templates::{TemplateError, template_params, validate_against_template};

// Re-export role system types from roles module (ADR-009).
pub use roles::{
    CapabilityCeiling, ContextRoleState, RoleAssignment, RoleError, UcanAttestation, UcanToken,
    assign_role, builtin_admin, builtin_author, builtin_broadcast_roles, builtin_member,
    builtin_observer, builtin_roles, builtin_subscriber, check_ceiling, validate_role_definition,
};

// Re-export builder and manager types for convenience.
pub use builder::{
    ContextCreationError, ContextCryptoProvider, ContextEventLogProvider,
    ContextTransportProvider, CreationReceipt, create_context,
};
pub use manager::ContextManager;

// ---------------------------------------------------------------------------
// ContextState
// ---------------------------------------------------------------------------

/// The five lifecycle states of an SCP context.
///
/// Valid transitions:
/// - `Creating -> Active` -- MLS group formed, initial parameters committed.
/// - `Active -> Closing` -- Close initiated by admin or governance.
/// - `Active -> Expired` -- TTL elapsed (automatic, no governance override).
/// - `Closing -> Closed` -- All members processed final events, keys destroyed.
///
/// `Closed` and `Expired` are terminal states -- no further transitions are
/// permitted. See ADR-008 for the full state machine specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextState {
    /// Context is being created. MLS group formation and parameter validation
    /// are in progress. If any step fails, the context is dropped without
    /// reaching `Active`.
    Creating,
    /// Context is fully operational. Messages, tool invocations, and membership
    /// changes are permitted according to the context's roles and capabilities.
    Active,
    /// Context closure has been initiated. Members have a window to process
    /// final events and verify summaries before keys are destroyed.
    Closing,
    /// Context is permanently closed. All key material has been destroyed.
    /// Content is unreadable for ephemeral and summary memory scopes.
    Closed,
    /// Context has expired due to TTL elapsing. This is a terminal state
    /// distinct from `Closed` -- TTL expiry skips the cooperative closing
    /// window. See spec section 5.10.
    Expired,
}

impl std::fmt::Display for ContextState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Creating => write!(f, "Creating"),
            Self::Active => write!(f, "Active"),
            Self::Closing => write!(f, "Closing"),
            Self::Closed => write!(f, "Closed"),
            Self::Expired => write!(f, "Expired"),
        }
    }
}

// ---------------------------------------------------------------------------
// ContextError
// ---------------------------------------------------------------------------

/// Errors produced by context lifecycle operations.
///
/// Error codes follow the `SCP-CTX-` prefix (range 2000-2999) as defined in
/// `.docs/standards/sdk-common.md`.
#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    /// A state transition was requested that is not permitted by the context
    /// lifecycle state machine. See [`state_machine::transition`] for valid
    /// transitions.
    #[error("invalid context state transition from {from} to {to}")]
    InvalidTransition {
        /// The current state of the context.
        from: ContextState,
        /// The requested target state.
        to: ContextState,
    },

    /// An attempt was made to modify an immutable capability ceiling.
    ///
    /// This error is returned when [`CeilingPolicy::Immutable`] is set and
    /// a ceiling modification is attempted.
    #[error("capability ceiling is immutable and cannot be modified")]
    CeilingImmutable,

    /// An operation was attempted that requires the context to be in the
    /// `Active` state, but the context is in a different state.
    #[error("context is not in Active state")]
    ContextNotActive,

    /// An operation was attempted on a context that has been permanently closed.
    /// All key material has been destroyed and the context cannot be used.
    #[error("context is closed")]
    ContextClosed,

    /// An operation was attempted on a context that has expired due to TTL.
    /// The context is in a terminal state and cannot be used.
    #[error("context has expired")]
    ContextExpired,

    /// Template validation failed: the [`ContextParams`] fields do not match
    /// the template definition. See [`templates::validate_against_template`].
    #[error(transparent)]
    TemplateMismatch(#[from] templates::TemplateError),
}

// ---------------------------------------------------------------------------
// ContextInner
// ---------------------------------------------------------------------------

/// Mutable interior of a [`ContextHandle`], protected by `RwLock`.
#[derive(Debug)]
struct ContextInner {
    /// Current lifecycle state.
    state: ContextState,
}

// ---------------------------------------------------------------------------
// ContextHandle
// ---------------------------------------------------------------------------

/// Thread-safe handle to an SCP context.
///
/// `ContextHandle` holds the context's identity, lifecycle state, and creation
/// parameters. It is `Send + Sync` -- safe to share across threads and async
/// tasks. Internal state mutations (state transitions) are serialized via
/// `tokio::sync::RwLock`.
///
/// The handle does not own the MLS group, event log, or transport connections.
/// Those are managed by the Context Manager (SCP-019/020).
///
/// # Examples
///
/// ```
/// use scp_core::context::{ContextHandle, ContextParams, ContextState};
///
/// let handle = ContextHandle::new("ctx-001".to_owned(), ContextParams::default());
/// ```
#[derive(Debug, Clone)]
pub struct ContextHandle {
    /// Unique identifier for this context.
    context_id: String,
    /// Creation-time parameters. Immutable after creation.
    params: ContextParams,
    /// Mutable state protected by `RwLock` for `Send + Sync` interior
    /// mutability.
    inner: Arc<RwLock<ContextInner>>,
}

impl ContextHandle {
    /// Creates a new context handle in the [`Creating`](ContextState::Creating)
    /// state.
    ///
    /// The context starts in `Creating` and must transition to `Active` after
    /// MLS group formation and parameter validation complete.
    #[must_use]
    pub fn new(context_id: String, params: ContextParams) -> Self {
        Self {
            context_id,
            params,
            inner: Arc::new(RwLock::new(ContextInner {
                state: ContextState::Creating,
            })),
        }
    }

    /// Returns the context's unique identifier.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns a reference to the context's creation parameters.
    #[must_use]
    pub const fn params(&self) -> &ContextParams {
        &self.params
    }

    /// Returns the context's current lifecycle state.
    ///
    /// Acquires a read lock on the interior state.
    pub async fn state(&self) -> ContextState {
        self.inner.read().await.state.clone()
    }

    /// Attempts to transition the context to a new state.
    ///
    /// Validates the transition via [`state_machine::transition`] and applies
    /// it atomically if valid. Returns the new state on success.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidTransition`] if the transition is not
    /// permitted by the lifecycle state machine.
    pub async fn transition_to(&self, target: &ContextState) -> Result<ContextState, ContextError> {
        let mut inner = self.inner.write().await;
        let new_state = transition(&inner.state, target)?;
        inner.state = new_state.clone();
        drop(inner);
        Ok(new_state)
    }
}

// ---------------------------------------------------------------------------
// Compile-time Send + Sync assertions
// ---------------------------------------------------------------------------

/// Compile-time assertion that all public handle types are `Send + Sync`.
///
/// This function is never called at runtime. Its sole purpose is to cause a
/// compilation error if any of the listed types fail to implement `Send + Sync`.
const fn _assert_send_sync() {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ContextHandle>();
    assert_send_sync::<ContextState>();
    assert_send_sync::<ContextParams>();
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn context_handle_starts_in_creating_state() {
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());
        assert_eq!(handle.state().await, ContextState::Creating);
    }

    #[tokio::test]
    async fn context_handle_context_id() {
        let handle = ContextHandle::new("ctx-42".to_owned(), ContextParams::default());
        assert_eq!(handle.context_id(), "ctx-42");
    }

    #[tokio::test]
    async fn context_handle_params() {
        let params = ContextParams {
            mode: ContextMode::Broadcast,
            ..ContextParams::default()
        };
        let handle = ContextHandle::new("ctx-1".to_owned(), params.clone());
        assert_eq!(*handle.params(), params);
    }

    #[tokio::test]
    async fn context_handle_transition_creating_to_active() {
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());
        let result = handle.transition_to(&ContextState::Active).await;
        assert_eq!(result.ok(), Some(ContextState::Active));
        assert_eq!(handle.state().await, ContextState::Active);
    }

    #[tokio::test]
    async fn context_handle_full_lifecycle() {
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        // Creating -> Active
        let result = handle.transition_to(&ContextState::Active).await;
        assert!(result.is_ok());
        assert_eq!(handle.state().await, ContextState::Active);

        // Active -> Closing
        let result = handle.transition_to(&ContextState::Closing).await;
        assert!(result.is_ok());
        assert_eq!(handle.state().await, ContextState::Closing);

        // Closing -> Closed
        let result = handle.transition_to(&ContextState::Closed).await;
        assert!(result.is_ok());
        assert_eq!(handle.state().await, ContextState::Closed);
    }

    #[tokio::test]
    async fn context_handle_expiry_lifecycle() {
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        // Creating -> Active
        let result = handle.transition_to(&ContextState::Active).await;
        assert!(result.is_ok());

        // Active -> Expired
        let result = handle.transition_to(&ContextState::Expired).await;
        assert!(result.is_ok());
        assert_eq!(handle.state().await, ContextState::Expired);
    }

    #[tokio::test]
    async fn context_handle_invalid_transition_preserves_state() {
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        // Creating -> Closing is invalid
        let result = handle.transition_to(&ContextState::Closing).await;
        assert!(result.is_err());

        // State should still be Creating
        assert_eq!(handle.state().await, ContextState::Creating);
    }

    #[tokio::test]
    async fn context_handle_closed_is_terminal() {
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());
        handle.transition_to(&ContextState::Active).await.ok();
        handle.transition_to(&ContextState::Closing).await.ok();
        handle.transition_to(&ContextState::Closed).await.ok();

        // Closed -> Active is invalid
        let result = handle.transition_to(&ContextState::Active).await;
        assert!(result.is_err());
        assert_eq!(handle.state().await, ContextState::Closed);
    }

    #[tokio::test]
    async fn context_handle_expired_is_terminal() {
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());
        handle.transition_to(&ContextState::Active).await.ok();
        handle.transition_to(&ContextState::Expired).await.ok();

        // Expired -> Active is invalid
        let result = handle.transition_to(&ContextState::Active).await;
        assert!(result.is_err());
        assert_eq!(handle.state().await, ContextState::Expired);
    }

    #[tokio::test]
    async fn context_handle_clone_shares_state() {
        let handle1 = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());
        let handle2 = handle1.clone();

        // Transition via handle1.
        handle1.transition_to(&ContextState::Active).await.ok();

        // handle2 should see the new state.
        assert_eq!(handle2.state().await, ContextState::Active);
    }

    #[test]
    fn context_state_display() {
        assert_eq!(format!("{}", ContextState::Creating), "Creating");
        assert_eq!(format!("{}", ContextState::Active), "Active");
        assert_eq!(format!("{}", ContextState::Closing), "Closing");
        assert_eq!(format!("{}", ContextState::Closed), "Closed");
        assert_eq!(format!("{}", ContextState::Expired), "Expired");
    }

    #[test]
    fn context_state_serialization_roundtrip() {
        let states = [
            ContextState::Creating,
            ContextState::Active,
            ContextState::Closing,
            ContextState::Closed,
            ContextState::Expired,
        ];
        for state in &states {
            let json = serde_json::to_string(state).ok();
            assert!(json.is_some(), "serialization failed for {state}");
            let deserialized: Result<ContextState, _> =
                serde_json::from_str(json.as_deref().unwrap_or(""));
            assert_eq!(
                deserialized.ok().as_ref(),
                Some(state),
                "roundtrip failed for {state}"
            );
        }
    }

    #[test]
    fn context_error_display_messages() {
        let err = ContextError::InvalidTransition {
            from: ContextState::Closed,
            to: ContextState::Active,
        };
        assert_eq!(
            format!("{err}"),
            "invalid context state transition from Closed to Active"
        );

        let err = ContextError::CeilingImmutable;
        assert_eq!(
            format!("{err}"),
            "capability ceiling is immutable and cannot be modified"
        );

        let err = ContextError::ContextNotActive;
        assert_eq!(format!("{err}"), "context is not in Active state");

        let err = ContextError::ContextClosed;
        assert_eq!(format!("{err}"), "context is closed");

        let err = ContextError::ContextExpired;
        assert_eq!(format!("{err}"), "context has expired");
    }

    /// Compile-time test: `ContextHandle` is `Send + Sync`.
    /// This test does not run any code -- it only needs to compile.
    #[test]
    fn handle_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ContextHandle>();
        assert_send_sync::<ContextState>();
        assert_send_sync::<ContextParams>();
    }
}
