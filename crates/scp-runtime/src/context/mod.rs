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
//!   parameters. `Send + Sync` via interior `Arc<ArcSwap<_>>`.
//! - [`ContextError`] -- Error type for context operations.
//! - [`ContextParams`] -- Full context configuration (re-exported from
//!   [`params`]).
//!
//! # State Machine
//!
//! The [`state_machine::transition`](scp_protocol::context::state_machine::transition) function validates state transitions and
//! returns the new state or an error. It is pure -- no side effects. The
//! Context Manager (SCP-019/020) is responsible for executing side effects.
//!
//! # Concurrency
//!
//! All public handle types are `Send + Sync`. The cached lifecycle state is
//! held in a lock-free `arc_swap::ArcSwap<ContextState>`: reads
//! ([`ContextHandle::state`]) are a lock-free atomic load. The cell is shared
//! cross-thread and written by more than one party (the owning per-context
//! actor's command loop and the off-actor FFI finalize path, ADR-049 §10), so
//! writes ([`ContextHandle::transition_to`]) validate then commit through a
//! compare-and-swap retry loop — making read-validate-write atomic under any
//! number of concurrent writers. See `.docs/standards/sdk-common.md`
//! Concurrency Model.

pub mod actor;
pub mod app_sandbox;
pub(crate) mod broadcast_helpers;
pub mod builder;
pub mod config;
pub(crate) mod economy_helpers;
pub(crate) mod economy_logic;
pub mod export_import;
pub mod governance;
pub(crate) mod governance_helpers;
pub(crate) mod governance_logic;
pub mod invitation_helpers;
pub(crate) mod lifecycle_helpers;
pub(crate) mod lifecycle_logic;
pub(crate) mod manager_methods;
pub(crate) mod messaging_helpers;
pub(crate) mod outlets_helpers;
pub mod persistence;
pub mod policy;
pub mod providers;
pub(crate) mod queries_helpers;
pub(crate) mod standing_helpers;
pub mod state;
pub mod supervisor;
pub(crate) mod trust_recovery_helpers;
pub mod ttl;
pub(crate) mod ttl_close_helpers;

pub mod outlets;

use std::sync::Arc;

use arc_swap::ArcSwap;

use scp_protocol::context::params;
use scp_protocol::context::{ContextError, ContextParams, ContextState, transition};

pub use config::{ContextConfig, ContextCreation};
// §7.3.8: the caveat/CID coupling type the FFI bridges mint from the validated
// invocation UCAN and thread into `Supervisor::invoke_outlet_with_economy`. The
// enclosing `outlets_helpers` module is `pub(crate)`; this single type is the
// only member the bridges must NAME, so it is re-exported here (and through
// `scp_core::context::outlets`) while the rest of the helpers stay internal.
pub use outlets_helpers::InvocationCaveatBinding;

// ---------------------------------------------------------------------------
// ContextHandle
// ---------------------------------------------------------------------------

/// Thread-safe handle to an SCP context.
///
/// `ContextHandle` holds the context's identity, lifecycle state, and creation
/// parameters. It is `Send + Sync` -- safe to share across threads and async
/// tasks. The lifecycle state lives in a lock-free
/// `arc_swap::ArcSwap<ContextState>`: reads are atomic loads. The cell is
/// shared cross-thread and written by more than one party — the owning
/// per-context actor's command loop and the off-actor FFI finalize path both
/// call [`transition_to`](ContextHandle::transition_to) on clones that share
/// the same `Arc<ArcSwap<ContextState>>`. Transitions are therefore committed
/// with a compare-and-swap retry loop so read-validate-write is atomic under
/// any number of writers (ADR-049 §10).
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
    /// Cached lifecycle state in a lock-free `ArcSwap` for `Send + Sync`
    /// interior mutability. Reads are atomic loads; transitions atomically
    /// store the validated next state. Clone-shared across handle clones so
    /// the FFI mutating path (`transition_to` through `&self`) and the close
    /// path observe the same cell.
    inner: Arc<ArcSwap<ContextState>>,
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
            inner: Arc::new(ArcSwap::from_pointee(ContextState::Creating)),
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

    /// Applies the spec §5.10 promotion mutation to `ContextParams`: memory scope
    /// transitions to `Full` AND the TTL is REMOVED (`ttl = None`). This is the
    /// only spec-authorized mutation of `ContextParams` after creation —
    /// promotion changes the opt-in contract from ephemeral to persistent, and a
    /// promoted context is permanent (no TTL).
    ///
    /// Clearing `ttl` here is the prune-immune promotion authority for the
    /// single-source TTL-deadline invariant (ADR-049 §9): `convergent_ttl_deadline`
    /// reads `params.ttl == None` as "promoted ⇒ no arm", so the promotion signal
    /// lives in the persisted snapshot params, NOT the prunable `ContextPromoted`
    /// event-log leaf (which remains only as the promotion RECORD).
    pub const fn promote_params(&mut self) {
        self.params.memory_scope = params::MemoryScope::Full;
        self.params.ttl = None;
    }

    /// Returns the context's current lifecycle state.
    ///
    /// A lock-free atomic load of the cached state (ADR-049 §10).
    #[must_use]
    pub fn state(&self) -> ContextState {
        ContextState::clone(&self.inner.load())
    }

    /// Attempts to transition the context to a new state.
    ///
    /// Validates the transition via [`state_machine::transition`](scp_protocol::context::state_machine::transition) and applies
    /// it atomically if valid. Returns the new state on success.
    ///
    /// # Concurrency
    ///
    /// The state cell is shared cross-thread: it is written both by the
    /// owning per-context actor's command loop (e.g. TTL expiry ->
    /// `Expired`, close -> `Closing`) and off-actor through the FFI
    /// finalize path, which persists a clone of this handle and calls
    /// `transition_to(&Closing)` on it (`napi/context.rs`
    /// `context_finalize_close_on`). Because `ContextHandle` is `Clone` and
    /// every clone shares the same `Arc<ArcSwap<ContextState>>`, a naive
    /// load-validate-store would let two writers race: one could validate
    /// against a state the other has already replaced and blindly store an
    /// invalid edge (e.g. `Expired -> Closing`).
    ///
    /// This method therefore uses a compare-and-swap retry loop: it
    /// validates against the *live* loaded state and only commits if the
    /// cell has not moved since the load. If another writer intervened, it
    /// retries against the fresh state. This makes read-validate-write
    /// atomic under any number of concurrent writers — a rejected
    /// transition never lands, and no committed update is ever lost.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidTransition`] if the transition is not
    /// permitted by the lifecycle state machine.
    pub fn transition_to(&self, target: &ContextState) -> Result<ContextState, ContextError> {
        loop {
            let current = self.inner.load();
            // Validate against the LIVE state; propagate a rejected edge as Err
            // without ever storing.
            let new_state = transition(&current, target)?;
            let previous = self
                .inner
                .compare_and_swap(&current, Arc::new(new_state.clone()));
            // `compare_and_swap` swaps only if the cell still held the pointer we
            // loaded; the returned guard is the value that was in the cell. When
            // it points at the same allocation we validated against, the swap
            // committed. Compare by data-pointer identity (both guards deref into
            // their backing `Arc<ContextState>` allocation).
            if std::ptr::eq(
                std::ptr::from_ref::<ContextState>(&previous),
                std::ptr::from_ref::<ContextState>(&current),
            ) {
                return Ok(new_state);
            }
            // Another writer moved the cell between load and swap; retry so the
            // validation is never stale.
        }
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
// Test-only convenience: build a Supervisor with providers + no-op
// persistence (ADR-049 §15).
// ---------------------------------------------------------------------------

/// Constructs a fresh test-only [`supervisor::Supervisor`].
///
/// Mirror of the legacy
/// `attach_test_supervisor(ContextManager::new(...))` shorthand: the
/// `ContextManager` type is gone in ADR-049 §15, so callers now build a
/// supervisor directly via [`supervisor::Supervisor::with_providers`].
///
/// Returns [`Arc<supervisor::Supervisor>`] — the supervisor is the
/// authoritative owner of every per-context state, provider, and
/// governance engine, and exposes the public API previously rooted on
/// `ContextManager`.
///
/// # Non-production
///
/// `persistence`, `payment_adapter`, `event_tx`, and `clock` default to
/// `None` (i.e. no-op persistence and a `SystemClock`). The required
/// `mls_storage` provider is wired to an in-memory backend — a
/// test-only dev opt-in; production bridges supply a real `Storage`.
/// Tests that exercise any of those specific surfaces must construct
/// their own supervisor explicitly via
/// [`supervisor::Supervisor::with_providers`].
#[cfg(any(test, feature = "testing"))]
#[must_use]
pub fn test_supervisor(
    crypto: Arc<crate::crypto::mls::provider::NodeMlsFactory>,
    transport: Box<dyn builder::ContextTransportProvider>,
    event_log: Box<dyn builder::ContextEventLogProvider>,
    key_resolver: scp_protocol::context::governance::KeyResolver,
) -> Arc<supervisor::Supervisor> {
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            scp_platform::in_memory::InMemoryStorage::new(),
        )),
    );
    supervisor::Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        None,
        None,
        None,
        None,
        mls_storage,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_protocol::context::ContextMode;

    #[tokio::test]
    async fn context_handle_starts_in_creating_state() {
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());
        assert_eq!(handle.state(), ContextState::Creating);
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
        let result = handle.transition_to(&ContextState::Active);
        assert_eq!(result.ok(), Some(ContextState::Active));
        assert_eq!(handle.state(), ContextState::Active);
    }

    #[tokio::test]
    async fn context_handle_full_lifecycle() {
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        // Creating -> Active
        let result = handle.transition_to(&ContextState::Active);
        assert!(result.is_ok());
        assert_eq!(handle.state(), ContextState::Active);

        // Active -> Closing
        let result = handle.transition_to(&ContextState::Closing);
        assert!(result.is_ok());
        assert_eq!(handle.state(), ContextState::Closing);

        // Closing -> Closed
        let result = handle.transition_to(&ContextState::Closed);
        assert!(result.is_ok());
        assert_eq!(handle.state(), ContextState::Closed);
    }

    #[tokio::test]
    async fn context_handle_expiry_lifecycle() {
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        // Creating -> Active
        let result = handle.transition_to(&ContextState::Active);
        assert!(result.is_ok());

        // Active -> Expired
        let result = handle.transition_to(&ContextState::Expired);
        assert!(result.is_ok());
        assert_eq!(handle.state(), ContextState::Expired);
    }

    #[tokio::test]
    async fn context_handle_invalid_transition_preserves_state() {
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        // Creating -> Closing is invalid
        let result = handle.transition_to(&ContextState::Closing);
        assert!(result.is_err());

        // State should still be Creating
        assert_eq!(handle.state(), ContextState::Creating);
    }

    #[tokio::test]
    async fn context_handle_closed_is_terminal() {
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());
        handle.transition_to(&ContextState::Active).ok();
        handle.transition_to(&ContextState::Closing).ok();
        handle.transition_to(&ContextState::Closed).ok();

        // Closed -> Active is invalid
        let result = handle.transition_to(&ContextState::Active);
        assert!(result.is_err());
        assert_eq!(handle.state(), ContextState::Closed);
    }

    #[tokio::test]
    async fn context_handle_expired_is_terminal() {
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());
        handle.transition_to(&ContextState::Active).ok();
        handle.transition_to(&ContextState::Expired).ok();

        // Expired -> Active is invalid
        let result = handle.transition_to(&ContextState::Active);
        assert!(result.is_err());
        assert_eq!(handle.state(), ContextState::Expired);
    }

    #[tokio::test]
    async fn context_handle_clone_shares_state() {
        let handle1 = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());
        let handle2 = handle1.clone();

        // Transition via handle1.
        handle1.transition_to(&ContextState::Active).ok();

        // handle2 should see the new state.
        assert_eq!(handle2.state(), ContextState::Active);
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

// The agent-binding live-pipeline tests live in their own file (the whole file
// is `#![cfg(test)]`). The `mod` declaration is placed at the very END of this
// module, after the trailing `#[cfg(test)] mod tests` block, so all test-only
// items sit together at the tail of the module.
#[cfg(test)]
mod agent_binding_pipeline_tests;
