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

pub mod broadcast;
pub mod builder;
pub mod close;
pub mod governance;
pub mod invitation;
pub mod manager;
pub mod membership;
pub mod memory_scope;
pub mod nesting;
pub mod params;
pub mod policy;
pub mod promotion;
pub mod providers;
pub mod roles;
pub mod standing;
pub mod state_machine;
pub mod templates;
pub mod tools;
pub mod ttl;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

/// Converts a `context_id` string to a deterministic 32-byte array using SHA-256.
///
/// This is the **canonical** context ID byte representation used across all
/// context operations: builder, manager, TTL, memory scope, and any code that
/// needs a `[u8; 32]` from a context ID string. Using SHA-256 ensures:
/// - Fixed output size regardless of input length (no truncation/collision).
/// - Uniform distribution (suitable as cryptographic key material identifiers).
/// - No information leakage about input length (unlike zero-padding).
///
/// # CRITICAL: All modules MUST use this function.
/// Using raw UTF-8 bytes (truncation/zero-padding) produces different values
/// than SHA-256 for the same input, causing crypto operations to address the
/// wrong MLS groups, sender keys, and event logs.
#[must_use]
pub fn context_id_bytes(context_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(context_id.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

// broadcast::validate_messages_read_ucan is intentionally module-private
// after RED-012 fix (wildcard rejection). Callers use BroadcastContext methods.

// Re-export all parameter types for convenience.
pub use params::{
    Capability, CeilingPolicy, ContextMode, ContextParams, FieldVisibility, GovernanceModel,
    MemoryScope, MetadataVisibilityPolicy, ProjectionOverride, ProjectionPolicy, ProjectionRule,
    PromotionPolicy, PublicMetadata, RoleDefinition, RuntimeMetadata, TemplateId, ToolRegistration,
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
    ContextCreationError, ContextCryptoProvider, ContextEventLogProvider, ContextTransportProvider,
    CreationReceipt, EventLogHandle, MlsGroupHandle, SenderKeyHandle, create_context,
};
pub use manager::{
    ContentKeysRotatedResult, ContextManager, ContextPersistence, ContextSnapshot,
    GovernanceActionResult, GovernanceReconfiguredResult, ProposalOutcome,
    ReadAccessRestoredResult, ReadAccessRevokedResult, WriteAccessRestoredResult,
    WriteAccessRevokedResult,
};

// Re-export membership types.
pub use membership::{
    ContextEvent, DEFAULT_BUFFER_CAPACITY, KeyPackage, MAX_BUFFER_CAPACITY, MIN_BUFFER_CAPACITY,
    MemberInfo, MembershipState, ReceiveBuffer,
};

// Re-export memory scope and key destruction types (SCP-067).
pub use memory_scope::{
    DeletionResponseStatus, DestructionMethod, EphemeralContextMetadata, KeyDestructionAttestation,
    KeyDestructionLevel, KeyDestructionOrchestrator, PlatformAttestation,
    PublishableKeyDestructionAttestation, RelayDeletionRequest, RelayDeletionTracker,
    validate_memory_scope_for_broadcast,
};

// Re-export nesting types (SCP-134, spec section 5.13).
pub use nesting::{
    ApprovalRequirement, ContextNesting, MAX_NESTING_DEPTH, MlsGroupContextExtension, NestingError,
    OnSeverPolicy, ParentGovernanceConfig, ParentRef, SeverAction, compute_ceiling_intersection,
    validate_child_ttl, validate_nesting_depth,
};

// Re-export auto-accept policy types (SCP-135).
pub use policy::{
    AutoAcceptPolicy, PolicyStorageError, RateLimit, TrustRequirement, auto_accept_allowed,
    delete_auto_accept_policy, get_auto_accept_policy, has_tool_capabilities, requires_payment,
    set_auto_accept_policy,
};

// Re-export invitation evaluation pipeline types (SCP-137).
pub use invitation::{
    EvaluationDecision, InvitationError, RateLimitTracker, SpendingContext, TrustOracle,
    evaluate_invitation,
};

// Re-export standing channel types (SCP-138).
pub use standing::{StandingChannelError, StandingChannelManager};

// Re-export governance types (SCP-129, ADR-031).
pub use governance::{
    ConflictResolution, DeadlockJustification, GovernanceAction, GovernanceContext,
    GovernanceEngine, GovernanceError, GovernanceEvent, GovernanceModelConfig, GovernanceProposal,
    GovernanceReconfigAction, ProposalId, ProposalStatus, RejectionReason, RevocationScope,
    SignedVote, SingleAdminEngine, VoteType, majority::MajorityVoteEngine,
    multisig::ThresholdEngine, sign_vote, unanimity::UnanimityEngine, verify_vote,
};

// Re-export broadcast context types (SCP-227, spec section 5.14, #101).
pub use broadcast::{
    AuthorBlockResult, AuthorState, AuthorStateSnapshot, BlockResult, BroadcastAdmission,
    BroadcastContext, BroadcastContextSnapshot, KeyRequestDecision, SubscriberRecord,
    SubscriberRegistration, SubscriptionResult, UnsubscribeResult,
};

// Re-export TTL management types (SCP-021, SCP-066).
pub use ttl::{CloseResult, TtlExtension, TtlTimer};
pub use ttl::{
    ExtensionConsentMode, TtlEnforcer, TtlError, TtlExtensionProposal, TtlPolicy, TtlTimerHandle,
    check_ttl, consent_mode_for_member_count,
};

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

    /// A membership operation failed (join, leave).
    #[error("membership operation failed: {0}")]
    MembershipFailed(String),

    /// A crypto operation failed during a membership or messaging operation.
    #[error("crypto operation failed: {0}")]
    CryptoFailed(String),

    /// A transport operation failed during messaging.
    #[error("transport operation failed: {0}")]
    TransportFailed(String),

    /// An event log operation failed.
    #[error("event log operation failed: {0}")]
    EventLogFailed(String),

    /// The sender does not have the required UCAN capability.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// The specified member was not found in the context.
    #[error("member not found: {0}")]
    MemberNotFound(String),

    /// A key package validation failed.
    #[error("invalid key package: {0}")]
    InvalidKeyPackage(String),

    /// A governance action would exceed a protocol-level collection size limit
    /// (§5.9). The message includes the limit value for debuggability.
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),

    /// An invalid memory scope was requested for a broadcast context.
    ///
    /// Broadcast contexts only support `MemoryScope::Full` because they lack
    /// MLS group management and cannot deliver the key destruction semantics
    /// required by `Ephemeral` and `Summary` scopes.
    #[error("broadcast contexts only support MemoryScope::Full")]
    InvalidMemoryScopeForBroadcast,

    /// An action-payment integration error occurred during a paid action.
    ///
    /// Wraps [`crate::economy::IntegrationError`] to preserve the specific
    /// error variant (authorization failure, cost insufficient, adapter error,
    /// etc.) rather than type-erasing to a string.
    ///
    /// See spec section 19.2.2.
    #[error("payment integration failed: {0}")]
    IntegrationFailed(#[from] crate::economy::IntegrationError),

    /// A persistence operation failed (store or load).
    ///
    /// Returned when the [`ContextPersistence`] provider reports an error
    /// during context or broadcast state persistence or restoration.
    #[error("persistence failed: {0}")]
    PersistenceFailed(String),

    /// A governance operation failed (proposal, vote, engine error).
    ///
    /// Returned when the [`GovernanceEngine`] reports an error during
    /// proposal creation, voting, or resolution.
    #[error("governance failed: {0}")]
    GovernanceFailed(String),

    /// Context creation failed due to invalid parameters or internal error.
    #[error("creation failed: {0}")]
    CreationFailed(String),

    /// A restore governance action was attempted on a member whose access
    /// was never revoked. Per §5.9: restore-when-never-revoked returns this
    /// error instead of silently succeeding.
    #[error("nothing to restore: {0}")]
    NothingToRestore(String),
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
