//! Context lifecycle types for SCP.
//!
//! This module implements the context lifecycle as a seven-state finite state
//! machine: `Creating -> Active -> Closing -> Closed`, with `Expired` as a
//! terminal state reachable from `Active` when TTL elapses, and
//! `MigratingOut -> Tombstoned` as the migration path from `Active`.
//! See ADR-008 in `.docs/adrs/phase-2.md` and spec §5.11A.
//!
//! # Types
//!
//! - [`ContextState`] -- The seven lifecycle states.
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

pub mod actor;
pub mod app_sandbox;
pub(crate) mod broadcast_helpers;
pub mod builder;
pub(crate) mod economy_helpers;
pub mod export_import;
pub mod governance;
pub(crate) mod governance_helpers;
pub mod key_destruction;
pub(crate) mod lifecycle_helpers;
pub mod manager;
pub(crate) mod manager_methods;
pub(crate) mod messaging_helpers;
pub mod policy;
pub mod providers;
pub(crate) mod queries_helpers;
pub(crate) mod standing_helpers;
pub mod supervisor;
pub(crate) mod tools_helpers;
pub(crate) mod trust_recovery_helpers;
pub mod ttl;

pub mod tools;

use std::sync::Arc;

use tokio::sync::RwLock;

use scp_protocol::context::params;
use scp_protocol::context::{
    ContextError, ContextParams, ContextState, context_id_bytes, transition,
};

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
/// use scp_runtime::context::ContextHandle;
/// use scp_protocol::context::{ContextParams, ContextState};
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

    /// Transitions the memory scope to `Full` during context promotion
    /// (§5.10). This is the only spec-authorized mutation of `ContextParams`
    /// after creation — promotion changes the opt-in contract from ephemeral
    /// to persistent.
    pub const fn promote_memory_scope(&mut self) {
        self.params.memory_scope = params::MemoryScope::Full;
    }

    /// Returns the context's current lifecycle state.
    ///
    /// Acquires a read lock on the interior state.
    pub async fn state(&self) -> ContextState {
        self.inner.read().await.state.clone()
    }

    /// Attempts a non-blocking read of the context state.
    ///
    /// Returns `None` if the read lock cannot be acquired immediately (e.g.,
    /// a state transition is in progress). Used by [`ContextManager`] to
    /// check state synchronously inside a `Mutex` lock scope, avoiding
    /// TOCTOU races without holding the `MutexGuard` across `.await` points.
    #[must_use]
    pub fn try_read_state(&self) -> Option<ContextState> {
        self.inner.try_read().ok().map(|g| g.state.clone())
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

// ---------------------------------------------------------------------------
// Test-only convenience: attach a fresh Supervisor to a ContextManager.
// ---------------------------------------------------------------------------

/// Wraps a manager in an Arc + attaches a fresh test-only Supervisor
/// (ADR-049 commit 12c.9c).
///
/// After commit 12c.9c every `ContextManager` method that forwards to
/// the hoisted messaging / broadcast / governance / economy helpers
/// goes through `self.supervisor().ok_or_else(...)?`. Tests that
/// invoke those methods directly on a fresh manager MUST first call
/// this wrapper so the `Weak<Supervisor>` back-pointer is populated;
/// otherwise the forwarder returns [`ContextError::NotInitialized`].
///
/// Returns [`Arc<manager::ContextManager>`] so tests can continue to
/// access `manager.contexts`, `manager.create_context(...)`, etc. via
/// [`std::sync::Arc`] auto-deref.
///
/// # Non-production
///
/// The supervisor is created via
/// [`supervisor::Supervisor::for_query_shim`] which installs no-op
/// persistence and saga journals. Tests that exercise those specific
/// subsystems must construct their own supervisor explicitly.
///
/// # Supervisor lifetime
///
/// The constructed [`std::sync::Arc<supervisor::Supervisor>`] is
/// leaked via [`std::mem::forget`] so the supervisor outlives this
/// stack frame. The manager holds only a
/// [`std::sync::Weak<supervisor::Supervisor>`] back-pointer; without
/// the leak, the supervisor's last strong reference would drop here
/// and the `Weak` would become immediately stale, which would cause
/// every forwarder call on `manager` to return `NotInitialized`.
/// Leaking is acceptable in test-only code — the process exits
/// shortly and the OS reclaims memory. Production callers (FFI
/// bridges, `Node`, `scp-node`) construct the supervisor with a
/// long-lived strong reference (e.g. `BridgeInstance::supervisor:
/// Arc<Supervisor>`), so no leak is needed there.
///
/// # Panics
///
/// Panics if [`supervisor::Supervisor::attach_context_manager`]
/// returns an error. That happens only on misuse (attaching a
/// manager that has already been bound to a different supervisor) —
/// a test-only contract violation.
#[cfg(any(test, feature = "testing"))]
#[allow(
    clippy::panic,
    reason = "test-only helper: attach failure is a contract violation and should abort the test"
)]
#[must_use]
pub fn attach_test_supervisor(mgr: manager::ContextManager) -> Arc<manager::ContextManager> {
    let manager = Arc::new(mgr);
    let supervisor = Arc::new(supervisor::Supervisor::for_query_shim());
    // The Result is infallible in practice: a freshly-constructed
    // Supervisor attaching a freshly-constructed manager cannot
    // observe an already-populated OnceLock. A programmer misuse
    // (attaching a manager that already has a different supervisor)
    // would hit the identity mismatch branch below; we intentionally
    // panic because tests should never attach twice.
    if let Err(e) = supervisor.attach_context_manager(&manager) {
        panic!("attach_test_supervisor: attach failed (contract violation): {e}");
    }
    // See doc comment "Supervisor lifetime" for the leak rationale.
    std::mem::forget(supervisor);
    manager
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_protocol::context::ContextMode;

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
