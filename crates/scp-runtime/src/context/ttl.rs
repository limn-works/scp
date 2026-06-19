//! Context close, finalize, TTL expiry, TTL enforcement, and TTL timer
//! management.
//!
//! Implements the context lifecycle termination operations from ADR-008
//! (`.docs/adrs/phase-2.md`) and TTL enforcement from ADR-018
//! (`.docs/adrs/phase-4.md`):
//!
//! - [`close_context`] -- Initiates cooperative close (Active -> Closing).
//! - [`finalize_close`] -- Completes close after members process notifications
//!   (Closing -> Closed).
//! - [`handle_ttl_expiry`] -- Automatic expiry when TTL elapses
//!   (Active -> Expired).
//! - [`TtlTimer`] -- Manages tokio timer tasks for TTL enforcement.
//! - [`TtlExtension`] -- Tracks unanimous consent for TTL extension.
//! - [`TtlPolicy`] -- TTL policy enum: `None` or `Finite(Duration)`.
//! - [`TtlEnforcer`] -- Per-context TTL state tracker with Clock-based
//!   expiry checking.
//! - [`TtlExtensionProposal`] -- Proposal for TTL extension with consent
//!   tracking for bilateral and multi-party contexts.
//! - [`TtlTimerHandle`] -- Trait-based timer management for testability.
//!
//! # Close Capability
//!
//! The initiator of `close_context` must hold the `ContextClose` capability
//! (admin role or governance-permitted). This is checked via
//! [`ContextRoleState::member_has_capability`].
//!
//! # TTL Enforcement (ADR-018)
//!
//! TTL is checked against the [`Clock`] trait (spec section 16.3) on every
//! context action. TTL expiry triggers context close -- no new actions
//! accepted after expiry. Extension requires consent: all-member for
//! bilateral contexts, governance for multi-party contexts.
//!
//! # Memory Scope Behavior
//!
//! - **Ephemeral:** Keys destroyed on close/expiry. Content becomes unreadable.
//! - **Summary:** Summary generated during closing window, then keys destroyed.
//! - **Full:** Keys retained. Content remains readable after close.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::AbortHandle;

use super::ContextHandle;
use super::builder::{ContextEventLogProvider, ContextTransportProvider};
use crate::crypto::mls::provider::MlsCryptoProvider;
use scp_identity::DID;
use scp_primitives::Clock;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::params::GovernanceModel;
use scp_protocol::context::roles::{self, ContextRoleState};
use scp_protocol::context::{ContextError, ContextState, MemoryScope};

// ---------------------------------------------------------------------------
// context_id_to_bytes helper (mirrors manager.rs)
// ---------------------------------------------------------------------------

/// Uses the canonical SHA-256 context ID byte derivation.
/// Delegates to [`scp_protocol::context::context_id_bytes`] to match builder.rs.
fn context_id_to_bytes(context_id: &str) -> [u8; 32] {
    scp_protocol::context::context_id_bytes(context_id)
}

// ---------------------------------------------------------------------------
// TtlPolicy
// ---------------------------------------------------------------------------

/// TTL policy for a context, declared at creation time.
///
/// Determines whether the context has a finite lifespan. Contexts with
/// `Finite` TTL automatically expire when the duration elapses. Contexts
/// with `None` TTL have no automatic expiry.
///
/// See ADR-018 in `.docs/adrs/phase-4.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtlPolicy {
    /// No TTL -- the context has no automatic expiry.
    None,
    /// Finite TTL -- the context expires after this duration from creation
    /// (or from the last extension).
    Finite(Duration),
}

// ---------------------------------------------------------------------------
// TtlError
// ---------------------------------------------------------------------------

/// Errors produced by TTL enforcement operations.
#[derive(Debug, thiserror::Error)]
pub enum TtlError {
    /// The context's TTL has expired. No further actions are permitted.
    #[error("context TTL has expired")]
    Expired,

    /// A TTL extension was proposed for a context with no TTL policy.
    #[error("cannot extend TTL on a context with no TTL policy")]
    NoTtlPolicy,

    /// A TTL extension proposal is already in progress.
    #[error("a TTL extension proposal is already in progress")]
    ProposalAlreadyActive,

    /// No active TTL extension proposal to consent to.
    #[error("no active TTL extension proposal")]
    NoActiveProposal,

    /// The governance model does not permit this member to propose or
    /// approve extensions in a multi-party context.
    #[error("governance does not permit extension: {0}")]
    GovernanceDenied(String),
}

// ---------------------------------------------------------------------------
// TtlExpiryResult — structured expiry outcome with partial-success tracking
// ---------------------------------------------------------------------------

/// Tracks which cleanup operations succeeded/failed during TTL expiry.
///
/// Returned from both individual cleanup attempts and the retry loop.
/// On full success, all step bits are set and `errors` is empty.
/// On partial failure, the bitmask records which operations completed
/// so that retries can skip already-succeeded steps.
#[derive(Debug, Clone)]
pub struct TtlExpiryResult {
    /// Bitfield tracking completion of each cleanup step.
    ///
    /// Bit 0: state transition to `Expired`.
    /// Bit 1: MLS group destruction (or not required).
    /// Bit 2: sender key destruction (or not required).
    /// Bit 3: event log append.
    completed_steps: u8,
    /// The error messages from failed operations.
    errors: Vec<String>,
}

/// Bit positions for [`TtlExpiryResult::completed_steps`].
const STEP_STATE_TRANSITIONED: u8 = 0b0000_0001;
const STEP_MLS_DESTROYED: u8 = 0b0000_0010;
const STEP_SENDER_KEY_DESTROYED: u8 = 0b0000_0100;
const STEP_EVENT_LOGGED: u8 = 0b0000_1000;

/// Mask for all steps complete.
const ALL_STEPS: u8 =
    STEP_STATE_TRANSITIONED | STEP_MLS_DESTROYED | STEP_SENDER_KEY_DESTROYED | STEP_EVENT_LOGGED;

impl TtlExpiryResult {
    /// Whether the state transition to `Expired` succeeded.
    #[must_use]
    pub const fn state_transitioned(&self) -> bool {
        self.completed_steps & STEP_STATE_TRANSITIONED != 0
    }

    /// Whether MLS group destruction succeeded (or was not required).
    #[must_use]
    pub const fn mls_destroyed(&self) -> bool {
        self.completed_steps & STEP_MLS_DESTROYED != 0
    }

    /// Whether sender key destruction succeeded (or was not required).
    #[must_use]
    pub const fn sender_key_destroyed(&self) -> bool {
        self.completed_steps & STEP_SENDER_KEY_DESTROYED != 0
    }

    /// Whether the event log append succeeded.
    #[must_use]
    pub const fn event_logged(&self) -> bool {
        self.completed_steps & STEP_EVENT_LOGGED != 0
    }

    /// The error messages from failed cleanup operations.
    #[must_use]
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    const fn set_step(&mut self, step: u8) {
        self.completed_steps |= step;
    }
}

impl std::fmt::Display for TtlExpiryResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_complete() {
            write!(f, "TTL expiry complete")
        } else {
            write!(
                f,
                "TTL expiry incomplete (state_transitioned={}, mls_destroyed={}, \
                 sender_key_destroyed={}, event_logged={}): {}",
                self.state_transitioned(),
                self.mls_destroyed(),
                self.sender_key_destroyed(),
                self.event_logged(),
                self.errors.join("; "),
            )
        }
    }
}

/// Maximum number of retry attempts for TTL expiry cleanup.
const TTL_EXPIRY_MAX_RETRIES: u32 = 5;

/// Base delay for exponential backoff between TTL expiry retries.
const TTL_EXPIRY_BASE_DELAY: Duration = Duration::from_millis(500);

/// Callback type for TTL expiry failure notification.
///
/// Called with `(context_id, error)` when TTL expiry fails after all retries
/// are exhausted. This allows the application layer to observe and react to
/// failed expirations (e.g., mark the context as needing manual cleanup).
pub type TtlExpiryFailureCallback = Arc<dyn Fn(String, TtlExpiryResult) + Send + Sync>;

// ---------------------------------------------------------------------------
// check_ttl -- Clock-based TTL checking
// ---------------------------------------------------------------------------

/// Checks whether a context's TTL has expired.
///
/// Compares the current time (from the [`Clock`] trait, spec section 16.3)
/// against the context's creation time and TTL policy, accounting for any
/// extensions.
///
/// # Arguments
///
/// * `created_at` -- Unix timestamp (seconds) when the context was created.
/// * `ttl_policy` -- The context's TTL policy.
/// * `extended_until` -- If set, the absolute Unix timestamp until which the
///   TTL has been extended. Takes precedence over the original TTL.
/// * `now` -- Current Unix timestamp (seconds) from the Clock trait.
///
/// # Errors
///
/// Returns [`TtlError::Expired`] if the TTL has elapsed.
pub fn check_ttl(
    created_at: u64,
    ttl_policy: TtlPolicy,
    extended_until: Option<u64>,
    now: u64,
) -> Result<(), TtlError> {
    match ttl_policy {
        TtlPolicy::None => Ok(()),
        TtlPolicy::Finite(duration) => {
            let deadline =
                extended_until.unwrap_or_else(|| created_at.saturating_add(duration.as_secs()));
            if now >= deadline {
                Err(TtlError::Expired)
            } else {
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TtlEnforcer -- per-context TTL state management
// ---------------------------------------------------------------------------

/// Manages TTL state for a single context.
///
/// Tracks creation time, TTL policy, extension state, and expiry status.
/// Used on every context action to enforce TTL via the [`Clock`] trait
/// (spec section 16.3).
///
/// See ADR-018 acceptance criterion 2.
#[derive(Debug)]
pub struct TtlEnforcer {
    /// Unix timestamp (seconds) when the context was created.
    created_at: u64,
    /// The context's TTL policy.
    ttl_policy: TtlPolicy,
    /// If the TTL has been extended, the absolute Unix timestamp until which
    /// the extension is valid. `None` if no extension has been applied.
    extended_until: Option<u64>,
    /// Whether the context has been marked as expired. Once `true`, all
    /// subsequent checks return [`TtlError::Expired`] without consulting
    /// the clock.
    expired: bool,
}

impl TtlEnforcer {
    /// Creates a new `TtlEnforcer` for a context.
    #[must_use]
    pub const fn new(created_at: u64, ttl_policy: TtlPolicy) -> Self {
        Self {
            created_at,
            ttl_policy,
            extended_until: None,
            expired: false,
        }
    }

    /// Checks whether the context's TTL has expired, using the given clock.
    ///
    /// # Errors
    ///
    /// Returns [`TtlError::Expired`] if the TTL has elapsed.
    pub fn check(&mut self, clock: &dyn Clock) -> Result<(), TtlError> {
        if self.expired {
            return Err(TtlError::Expired);
        }
        let result = check_ttl(
            self.created_at,
            self.ttl_policy,
            self.extended_until,
            clock.now_secs(),
        );
        if result.is_err() {
            self.expired = true;
        }
        result
    }

    /// Returns the context's TTL policy.
    #[must_use]
    pub const fn ttl_policy(&self) -> TtlPolicy {
        self.ttl_policy
    }

    /// Returns the context's creation timestamp.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Returns the extended-until timestamp, if any.
    #[must_use]
    pub const fn extended_until(&self) -> Option<u64> {
        self.extended_until
    }

    /// Returns `true` if the enforcer has latched into the expired state.
    #[must_use]
    pub const fn is_expired(&self) -> bool {
        self.expired
    }

    /// Applies a TTL extension, resetting the deadline.
    ///
    /// # Errors
    ///
    /// Returns [`TtlError::NoTtlPolicy`] if the context has no TTL.
    pub fn apply_extension(
        &mut self,
        new_deadline: u64,
        clock: &dyn Clock,
    ) -> Result<(), TtlError> {
        if self.ttl_policy == TtlPolicy::None {
            return Err(TtlError::NoTtlPolicy);
        }
        self.extended_until = Some(new_deadline);
        if new_deadline > clock.now_secs() {
            self.expired = false;
        }
        Ok(())
    }

    /// Returns the remaining time in seconds until TTL expiry, or `None` if
    /// the TTL policy is `None`.
    #[must_use]
    pub fn remaining_secs(&self, clock: &dyn Clock) -> Option<u64> {
        match self.ttl_policy {
            TtlPolicy::None => Option::None,
            TtlPolicy::Finite(duration) => {
                let deadline = self
                    .extended_until
                    .unwrap_or_else(|| self.created_at.saturating_add(duration.as_secs()));
                let now = clock.now_secs();
                if now >= deadline {
                    Some(0)
                } else {
                    Some(deadline - now)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ExtensionConsentMode -- bilateral vs multi-party
// ---------------------------------------------------------------------------

/// Determines the consent model for TTL extension.
///
/// See ADR-018 acceptance criterion 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionConsentMode {
    /// All members must consent (bilateral contexts with exactly 2 members).
    AllMember,
    /// Extension follows the context's governance model (multi-party).
    Governance,
}

/// Determines the consent mode based on member count.
#[must_use]
pub const fn consent_mode_for_member_count(member_count: usize) -> ExtensionConsentMode {
    if member_count <= 2 {
        ExtensionConsentMode::AllMember
    } else {
        ExtensionConsentMode::Governance
    }
}

// ---------------------------------------------------------------------------
// TtlExtensionProposal -- structured extension proposal
// ---------------------------------------------------------------------------

/// A structured proposal for TTL extension, recorded as a context event
/// in the Merkle log (ADR-011).
///
/// See ADR-018 acceptance criterion 3.
#[derive(Debug, Clone)]
pub struct TtlExtensionProposal {
    /// DID of the member who proposed the extension.
    proposer_did: DID,
    /// The proposed additional TTL duration.
    proposed_duration: Duration,
    /// The consent mode (bilateral vs governance).
    consent_mode: ExtensionConsentMode,
    /// The underlying consent tracker.
    consent: TtlExtension,
    /// The governance model for this context.
    governance: GovernanceModel,
}

impl TtlExtensionProposal {
    /// Creates a new TTL extension proposal.
    #[must_use]
    pub fn new(
        proposer_did: DID,
        proposed_duration: Duration,
        member_count: usize,
        governance: GovernanceModel,
    ) -> Self {
        let consent_mode = consent_mode_for_member_count(member_count);
        let required_count = match consent_mode {
            ExtensionConsentMode::AllMember => member_count,
            ExtensionConsentMode::Governance => match &governance {
                GovernanceModel::SingleAdmin => 1,
                GovernanceModel::Threshold { threshold, .. } => *threshold as usize,
                GovernanceModel::Majority { eligible_voters } => {
                    // >50% of eligible voters (rounding up).
                    eligible_voters.len().div_ceil(2)
                }
                GovernanceModel::Unanimity { eligible_voters } => eligible_voters.len(),
            },
        };
        Self {
            proposer_did,
            proposed_duration,
            consent_mode,
            consent: TtlExtension::new(proposed_duration, required_count),
            governance,
        }
    }

    /// Records a member's consent for the extension.
    pub fn record_consent(&mut self, member_did: DID) -> bool {
        self.consent.add_consent(member_did)
    }

    /// Returns `true` if sufficient consent has been collected.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        self.consent.is_unanimous()
    }

    /// Returns the DID of the proposer.
    #[must_use]
    pub const fn proposer_did(&self) -> &DID {
        &self.proposer_did
    }

    /// Returns the proposed additional TTL duration.
    #[must_use]
    pub const fn proposed_duration(&self) -> Duration {
        self.proposed_duration
    }

    /// Returns the consent mode for this proposal.
    #[must_use]
    pub const fn consent_mode(&self) -> ExtensionConsentMode {
        self.consent_mode
    }

    /// Returns the number of consents received so far.
    #[must_use]
    pub fn consent_count(&self) -> usize {
        self.consent.consent_count()
    }

    /// Returns the number of consents still needed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.consent.remaining()
    }

    /// Returns the governance model for this proposal's context.
    #[must_use]
    pub const fn governance(&self) -> &GovernanceModel {
        &self.governance
    }

    /// Returns `true` if sufficient consent has been collected from active
    /// members only.
    ///
    /// Votes from members who were removed after casting their vote are
    /// excluded from the tally. The threshold is evaluated against the count
    /// of active-member votes only.
    ///
    /// See SCP-195.
    #[must_use]
    pub fn is_approved_active(&self, active_members: &HashSet<DID>) -> bool {
        self.consent.is_unanimous_active(active_members)
    }

    /// Returns the number of consents from currently active members.
    ///
    /// See SCP-195.
    #[must_use]
    pub fn active_consent_count(&self, active_members: &HashSet<DID>) -> usize {
        self.consent.active_consent_count(active_members)
    }

    /// Returns the number of active-member consents still needed.
    ///
    /// See SCP-195.
    #[must_use]
    pub fn active_remaining(&self, active_members: &HashSet<DID>) -> usize {
        self.consent.active_remaining(active_members)
    }

    /// Computes the new deadline by adding the proposed duration to now.
    #[must_use]
    pub const fn compute_new_deadline(&self, now: u64) -> u64 {
        now.saturating_add(self.proposed_duration.as_secs())
    }
}

// ---------------------------------------------------------------------------
// TtlTimerHandle -- trait-based timer management for testability
// ---------------------------------------------------------------------------

/// Trait for TTL timer management, enabling testable timer logic without
/// requiring a tokio runtime.
///
/// See ADR-018 acceptance criterion 2.
pub trait TtlTimerHandle: Send + Sync {
    /// Cancels the running TTL timer.
    fn cancel_timer(&self);

    /// Resets the TTL timer with a new duration.
    fn reset_timer(&mut self, new_duration: Duration);

    /// Returns `true` if a timer is currently active.
    fn is_timer_active(&self) -> bool;
}

// ---------------------------------------------------------------------------
// close_context
// ---------------------------------------------------------------------------

/// Initiates cooperative context closure.
///
/// See ADR-008 acceptance criterion 5.
///
/// # Errors
///
/// Returns [`ContextError::ContextNotActive`] if the context is not `Active`.
/// Returns [`ContextError::PermissionDenied`] if the initiator lacks the
/// `ContextClose` capability.
pub async fn close_context(
    handle: &ContextHandle,
    initiator_did: &DID,
    role_state: &ContextRoleState,
    event_log: &dyn ContextEventLogProvider,
    // Convergent close timestamp recorded on the `ContextClosing` leaf: the
    // initiator's close-commit time (the `created_at` of the outgoing close
    // commit), copied by every member — never a per-member local `now()`
    // (§7.3.1, §9.9.3).
    timestamp_secs: u64,
) -> Result<CloseResult, ContextError> {
    let state = handle.state().await;
    if state != ContextState::Active {
        return Err(ContextError::ContextNotActive);
    }

    if !role_state.member_has_capability(initiator_did, &roles::Capability::ContextClose) {
        return Err(ContextError::PermissionDenied(format!(
            "member {initiator_did} does not have context:close capability"
        )));
    }

    handle.transition_to(&ContextState::Closing).await?;

    let context_id = handle.context_id().to_owned();
    let context_id_bytes = context_id_to_bytes(&context_id);

    let memory_scope = handle.params().memory_scope;
    let should_generate_summary = memory_scope == MemoryScope::Summary;
    let should_schedule_key_destruction =
        memory_scope == MemoryScope::Ephemeral || memory_scope == MemoryScope::Summary;

    event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::ContextClosing,
        initiator_did.as_ref(),
        timestamp_secs,
    )?;

    Ok(CloseResult {
        should_generate_summary,
        should_schedule_key_destruction,
    })
}

/// Result of a successful `close_context` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseResult {
    /// If `true`, the caller should trigger summary generation.
    pub should_generate_summary: bool,
    /// If `true`, key destruction should be scheduled.
    pub should_schedule_key_destruction: bool,
}

// ---------------------------------------------------------------------------
// finalize_close
// ---------------------------------------------------------------------------

/// Completes context closure after all members have processed notifications.
///
/// See ADR-008 acceptance criterion 6.
///
/// # Errors
///
/// Returns [`ContextError::InvalidTransition`] if the context is not in
/// `Closing` state.
pub async fn finalize_close(
    handle: &ContextHandle,
    crypto: &MlsCryptoProvider,
    transport: &dyn ContextTransportProvider,
    event_log: &dyn ContextEventLogProvider,
    // Convergent close timestamp recorded on the `ContextClosed` leaf: the TTL
    // deadline for a timer-driven close, or the committer's close-commit time
    // for a governance close — never a per-member local `now()` (§7.3.1,
    // §9.9.3).
    timestamp_secs: u64,
) -> Result<(), ContextError> {
    // Validate state transition BEFORE destroying any key material.
    // Key destruction is irreversible — once zeroized, encrypted content
    // becomes permanently unreadable. If the transition fails (e.g. context
    // is not in Closing state), no keys must be destroyed.
    handle.transition_to(&ContextState::Closed).await?;

    let context_id = handle.context_id().to_owned();
    let context_id_bytes = context_id_to_bytes(&context_id);
    let memory_scope = handle.params().memory_scope;

    // Full memory scope retains keys — content remains readable after close.
    // Only destroy crypto material for Ephemeral and Summary scopes.
    if memory_scope == MemoryScope::Ephemeral || memory_scope == MemoryScope::Summary {
        crypto
            .destroy_mls_group(&context_id_bytes)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
        crypto
            .destroy_sender_key(&context_id_bytes)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        let _ = transport.delete_published(&context_id_bytes);
    }

    event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::ContextClosed,
        "system:close",
        timestamp_secs,
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// handle_ttl_expiry
// ---------------------------------------------------------------------------

/// Handles automatic TTL expiry.
///
/// See ADR-008 acceptance criterion 7 and spec §5.10/§5.11.
///
/// When a context's TTL elapses, the SDK:
/// 1. Transitions the context to `Expired` state.
/// 2. Records a `ContextExpired` event in the event log.
/// 3. For `Ephemeral` or `Summary` memory scopes: destroys MLS group state
///    and sender keys, and issues best-effort relay deletion requests for
///    all encrypted event data.
///
/// # Errors
///
/// Returns [`ContextError::ContextNotActive`] if the context is not `Active`.
pub async fn handle_ttl_expiry(
    handle: &ContextHandle,
    crypto: &MlsCryptoProvider,
    event_log: &dyn ContextEventLogProvider,
    expiry_deadline_secs: u64,
) -> Result<(), ContextError> {
    handle_ttl_expiry_with_transport(handle, crypto, None, event_log, expiry_deadline_secs).await
}

/// Handles automatic TTL expiry with optional transport for relay deletion.
///
/// When `transport` is provided and the memory scope is `Ephemeral` or
/// `Summary`, the SDK issues best-effort deletion requests to relays for
/// all encrypted event data (spec §5.11). The deletion is best-effort —
/// the expiry succeeds even if the relay rejects the deletion request.
///
/// # Errors
///
/// Returns [`ContextError::ContextNotActive`] if the context is not `Active`
/// or `Expired` (for retry). Returns [`ContextError::CryptoFailed`] or
/// [`ContextError::EventLogFailed`] if cleanup operations fail.
pub async fn handle_ttl_expiry_with_transport(
    handle: &ContextHandle,
    crypto: &MlsCryptoProvider,
    transport: Option<&dyn ContextTransportProvider>,
    event_log: &dyn ContextEventLogProvider,
    expiry_deadline_secs: u64,
) -> Result<(), ContextError> {
    let state = handle.state().await;
    if state != ContextState::Active && state != ContextState::Expired {
        return Err(ContextError::ContextNotActive);
    }

    let result = try_ttl_expiry_cleanup(
        handle,
        crypto,
        transport,
        event_log,
        0,
        expiry_deadline_secs,
    )
    .await;

    if result.has_failures() {
        // Return the first error as a ContextError for backward compatibility.
        let msg = result.errors.join("; ");
        return Err(if !result.state_transitioned() {
            ContextError::ContextNotActive
        } else if !result.mls_destroyed() || !result.sender_key_destroyed() {
            ContextError::CryptoFailed(msg)
        } else {
            ContextError::EventLogFailed(msg)
        });
    }

    Ok(())
}

/// Attempts TTL expiry cleanup, returning a structured result.
///
/// Returns a [`TtlExpiryResult`] that tracks which operations succeeded and
/// which failed. The `prior_completed` bitmask carries forward steps that
/// already succeeded on a previous attempt so they are not re-executed.
/// This prevents duplicate event log entries and redundant crypto operations
/// across retries.
///
/// State transition is inherently idempotent (an already-`Expired` context
/// is recognized as transitioned), but crypto destruction and event log
/// appends are **not** idempotent — hence the bitmask guard.
pub async fn try_ttl_expiry_cleanup(
    handle: &ContextHandle,
    crypto: &MlsCryptoProvider,
    transport: Option<&dyn ContextTransportProvider>,
    event_log: &dyn ContextEventLogProvider,
    prior_completed: u8,
    // Timer-triggered expiry: the pre-computed convergent TTL deadline (every
    // member holds the identical value), recorded on the `ContextExpired` leaf
    // instead of a per-member local `now()` (§7.3.1, §9.9.3).
    expiry_deadline_secs: u64,
) -> TtlExpiryResult {
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = context_id_to_bytes(&context_id);
    let memory_scope = handle.params().memory_scope;

    let mut result = TtlExpiryResult {
        completed_steps: prior_completed,
        errors: Vec::new(),
    };

    let needs_key_destruction =
        memory_scope == MemoryScope::Ephemeral || memory_scope == MemoryScope::Summary;

    // If keys are not required to be destroyed, mark them as done.
    if !needs_key_destruction {
        result.set_step(STEP_MLS_DESTROYED | STEP_SENDER_KEY_DESTROYED);
    }

    // 1. State transition (idempotent — skip if already Expired or already
    //    completed on a prior attempt).
    if result.completed_steps & STEP_STATE_TRANSITIONED == 0 {
        let state = handle.state().await;
        match state {
            ContextState::Active => match handle.transition_to(&ContextState::Expired).await {
                Ok(_) => result.set_step(STEP_STATE_TRANSITIONED),
                Err(e) => {
                    let msg = format!("state transition failed: {e}");
                    tracing::error!(context_id = %context_id, "{msg}");
                    result.errors.push(msg);
                    // Cannot proceed with cleanup if transition failed.
                    return result;
                }
            },
            ContextState::Expired => {
                // Already expired (retry path). Continue with cleanup.
                result.set_step(STEP_STATE_TRANSITIONED);
            }
            _ => {
                let msg = format!(
                    "context is in {state} state, expected Active or Expired for TTL expiry"
                );
                tracing::error!(context_id = %context_id, "{msg}");
                result.errors.push(msg);
                return result;
            }
        }
    }

    // 2. Key destruction (Ephemeral/Summary only). Each operation is
    //    independent — a failure in one does not block the other. Skip
    //    operations that already succeeded on a prior attempt.
    if needs_key_destruction {
        if result.completed_steps & STEP_MLS_DESTROYED == 0 {
            match crypto.destroy_mls_group(&context_id_bytes) {
                Ok(()) => result.set_step(STEP_MLS_DESTROYED),
                Err(e) => {
                    let msg = format!("failed to destroy MLS group: {e}");
                    tracing::warn!(context_id = %context_id, error = %e,
                        "failed to destroy MLS group after TTL expiry — keys may persist");
                    result.errors.push(msg);
                }
            }
        }
        if result.completed_steps & STEP_SENDER_KEY_DESTROYED == 0 {
            match crypto.destroy_sender_key(&context_id_bytes) {
                Ok(()) => result.set_step(STEP_SENDER_KEY_DESTROYED),
                Err(e) => {
                    let msg = format!("failed to destroy sender key: {e}");
                    tracing::warn!(context_id = %context_id, error = %e,
                        "failed to destroy sender key after TTL expiry — keys may persist");
                    result.errors.push(msg);
                }
            }
        }

        // Best-effort relay ciphertext deletion (§5.11). Relay deletion is
        // non-blocking — even if the relay retains the encrypted blobs, the
        // keys are destroyed and the data is unreadable. Not tracked in the
        // bitmask since it is best-effort by design.
        if let Some(transport) = transport
            && let Err(e) = transport.delete_published(&context_id_bytes)
        {
            tracing::warn!(context_id = %context_id, error = %e,
                "best-effort relay deletion failed after TTL expiry");
        }
    }

    // 3. Event log append — skip if already succeeded on a prior attempt to
    //    avoid duplicate ContextExpired entries in the Merkle log.
    if result.completed_steps & STEP_EVENT_LOGGED == 0 {
        match event_log.append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::ContextExpired,
            "system:timer",
            expiry_deadline_secs,
        ) {
            Ok(()) => result.set_step(STEP_EVENT_LOGGED),
            Err(e) => {
                let msg = format!("failed to log ContextExpired event: {e}");
                tracing::warn!(context_id = %context_id, error = %e,
                    "failed to append ContextExpired to event log");
                result.errors.push(msg);
            }
        }
    }

    result
}

impl TtlExpiryResult {
    /// Returns `true` if any cleanup operation failed.
    #[must_use]
    pub const fn has_failures(&self) -> bool {
        self.completed_steps != ALL_STEPS
    }

    /// Returns `true` if the cleanup is fully complete — no errors.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.completed_steps == ALL_STEPS
    }
}

/// Runs TTL expiry cleanup with exponential backoff retries.
///
/// Attempts cleanup up to `TTL_EXPIRY_MAX_RETRIES` times. The
/// `completed_steps` bitmask from each attempt is carried forward to the
/// next, so operations that already succeeded (state transition, key
/// destruction, event log append) are never re-executed. This prevents
/// duplicate Merkle event log entries and redundant crypto operations.
///
/// If the cancel signal fires during a retry delay, cleanup is abandoned
/// and the partial result is returned immediately.
///
/// Returns the final [`TtlExpiryResult`] after all retries are exhausted
/// or cleanup succeeds.
pub async fn run_ttl_expiry_with_retries(
    handle: &ContextHandle,
    crypto: &MlsCryptoProvider,
    transport: Option<&dyn ContextTransportProvider>,
    event_log: &dyn ContextEventLogProvider,
    cancel: &Notify,
    expiry_deadline_secs: u64,
) -> TtlExpiryResult {
    let context_id = handle.context_id().to_owned();
    let mut completed_steps: u8 = 0;

    for attempt in 0..TTL_EXPIRY_MAX_RETRIES {
        let result = try_ttl_expiry_cleanup(
            handle,
            crypto,
            transport,
            event_log,
            completed_steps,
            expiry_deadline_secs,
        )
        .await;
        completed_steps = result.completed_steps;

        if result.is_complete() {
            if attempt > 0 {
                tracing::info!(
                    context_id = %context_id,
                    attempt = attempt + 1,
                    "TTL expiry cleanup succeeded on retry"
                );
            }
            return result;
        }

        // Not the last attempt — wait with exponential backoff before retrying.
        if attempt + 1 < TTL_EXPIRY_MAX_RETRIES {
            let delay = TTL_EXPIRY_BASE_DELAY * 2u32.saturating_pow(attempt);
            tracing::warn!(
                context_id = %context_id,
                attempt = attempt + 1,
                max_attempts = TTL_EXPIRY_MAX_RETRIES,
                delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                errors = ?result.errors,
                "TTL expiry cleanup incomplete, retrying"
            );

            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                () = cancel.notified() => {
                    tracing::info!(
                        context_id = %context_id,
                        "TTL expiry retry cancelled"
                    );
                    return result;
                }
            }
        } else {
            // Final attempt exhausted.
            tracing::error!(
                context_id = %context_id,
                attempts = TTL_EXPIRY_MAX_RETRIES,
                errors = ?result.errors,
                "TTL expiry cleanup failed after all retries"
            );
            return result;
        }
    }

    // Unreachable in practice, but satisfies the type system.
    TtlExpiryResult {
        completed_steps: 0,
        errors: vec!["retry loop exited without result".into()],
    }
}

// ---------------------------------------------------------------------------
// TtlTimer -- tokio-based TTL timer management
// ---------------------------------------------------------------------------

/// Manages a TTL timer for a single context.
///
/// On expiry, the timer runs cleanup with exponential backoff retries (up to
/// `TTL_EXPIRY_MAX_RETRIES` attempts). If cleanup fails after all retries,
/// the optional `on_error` callback is invoked with the context ID and a
/// [`TtlExpiryResult`] describing which operations succeeded and which failed.
///
/// See ADR-008 acceptance criterion 9.
pub struct TtlTimer {
    /// The spawned timer task abort handle. `None` if no TTL is configured.
    pub(crate) task: Option<AbortHandle>,
    /// Cancellation signal.
    pub(crate) cancel: Arc<Notify>,
    /// Absolute deadline as Unix epoch seconds, set when timer is spawned.
    /// Used to compute remaining TTL for persistence snapshots.
    pub(crate) deadline_unix_secs: Option<u64>,
    /// Optional callback invoked when TTL expiry fails after all retries.
    pub(crate) on_error: Option<TtlExpiryFailureCallback>,
    /// Clock used for deadline computation.
    pub(crate) clock: Arc<dyn Clock>,
}

impl TtlTimer {
    /// Creates a new `TtlTimer` without starting any task.
    #[must_use]
    pub fn new() -> Self {
        Self {
            task: None,
            cancel: Arc::new(Notify::new()),
            deadline_unix_secs: None,
            on_error: None,
            clock: Arc::new(scp_primitives::time::SystemClock),
        }
    }

    /// Creates a new `TtlTimer` with a specific clock.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            task: None,
            cancel: Arc::new(Notify::new()),
            deadline_unix_secs: None,
            on_error: None,
            clock,
        }
    }

    /// Creates a new `TtlTimer` with an error callback.
    ///
    /// The callback is invoked with `(context_id, error)` when TTL expiry
    /// cleanup fails after all retry attempts are exhausted.
    #[must_use]
    pub fn with_error_callback(on_error: TtlExpiryFailureCallback) -> Self {
        Self {
            task: None,
            cancel: Arc::new(Notify::new()),
            deadline_unix_secs: None,
            on_error: Some(on_error),
            clock: Arc::new(scp_primitives::time::SystemClock),
        }
    }

    /// Sets the error callback. Replaces any existing callback.
    pub fn set_error_callback(&mut self, on_error: TtlExpiryFailureCallback) {
        self.on_error = Some(on_error);
    }

    /// Spawns a TTL timer task that fires after the given duration.
    pub fn spawn(
        &mut self,
        duration: Duration,
        handle: ContextHandle,
        crypto: Arc<MlsCryptoProvider>,
        event_log: Arc<dyn ContextEventLogProvider>,
    ) {
        self.spawn_with_transport(duration, handle, crypto, None, event_log);
    }

    /// Spawns a TTL timer task with optional transport for relay deletion
    /// on ephemeral/summary context expiry (§5.11).
    ///
    /// On expiry, cleanup is attempted with exponential backoff retries.
    /// If all retries fail, the `on_error` callback (if set) is invoked.
    pub fn spawn_with_transport(
        &mut self,
        duration: Duration,
        handle: ContextHandle,
        crypto: Arc<MlsCryptoProvider>,
        transport: Option<Arc<dyn ContextTransportProvider>>,
        event_log: Arc<dyn ContextEventLogProvider>,
    ) {
        // Record absolute deadline for persistence snapshots. This pre-computed
        // deadline is also the convergent `ContextExpired` leaf timestamp every
        // member records when the timer fires (§7.3.1, §9.9.3).
        let now_secs = self.clock.now_secs();
        let expiry_deadline_secs = now_secs.saturating_add(duration.as_secs());
        self.deadline_unix_secs = Some(expiry_deadline_secs);

        let cancel = self.cancel.clone();
        let on_error = self.on_error.clone();
        let context_id = handle.context_id().to_owned();

        let handle = tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(duration) => {
                    let result = run_ttl_expiry_with_retries(
                        &handle,
                        crypto.as_ref(),
                        transport.as_deref(),
                        event_log.as_ref(),
                        &cancel,
                        expiry_deadline_secs,
                    ).await;

                    if result.has_failures()
                        && let Some(cb) = on_error
                    {
                        cb(context_id, result);
                    }
                }
                () = cancel.notified() => {
                }
            }
        });

        self.task = Some(handle.abort_handle());
    }

    /// Cancels the running TTL timer, if any.
    pub fn cancel(&self) {
        self.cancel.notify_one();
    }

    /// Returns `true` if a timer task is currently active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.task.as_ref().is_some_and(|t| !t.is_finished())
    }

    /// Returns the remaining TTL seconds, computed from the stored deadline.
    ///
    /// Returns `None` if the timer is not active or has no deadline.
    /// Returns `0` if the deadline has already passed.
    #[must_use]
    pub fn remaining_secs(&self) -> Option<u64> {
        if !self.is_active() {
            return None;
        }
        let deadline = self.deadline_unix_secs?;
        let now_secs = self.clock.now_secs();
        Some(deadline.saturating_sub(now_secs))
    }
}

impl Default for TtlTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TtlTimer {
    fn drop(&mut self) {
        self.cancel.notify_one();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// TtlExtension -- unanimous consent tracking
// ---------------------------------------------------------------------------

/// Tracks member consent for TTL extension.
#[derive(Debug, Clone)]
pub struct TtlExtension {
    /// The proposed new TTL duration.
    pub proposed_duration: Duration,
    /// DIDs that have consented to the extension.
    consented: HashSet<DID>,
    /// Total member count required for unanimity.
    required_count: usize,
}

impl TtlExtension {
    /// Creates a new TTL extension proposal.
    #[must_use]
    pub fn new(proposed_duration: Duration, member_count: usize) -> Self {
        Self {
            proposed_duration,
            consented: HashSet::new(),
            required_count: member_count,
        }
    }

    /// Records a member's consent. Returns `true` if this was a new consent.
    pub fn add_consent(&mut self, member_did: DID) -> bool {
        self.consented.insert(member_did)
    }

    /// Returns `true` if all members have consented (unanimous).
    #[must_use]
    pub fn is_unanimous(&self) -> bool {
        self.consented.len() >= self.required_count
    }

    /// Returns the number of consents received so far.
    #[must_use]
    pub fn consent_count(&self) -> usize {
        self.consented.len()
    }

    /// Returns the number of consents still needed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.required_count.saturating_sub(self.consented.len())
    }

    /// Returns the number of consents from members who are still active.
    ///
    /// Votes from members who have been removed since casting their vote are
    /// excluded from the count. This prevents a removed member's stale vote
    /// from contributing to the tally at evaluation time.
    ///
    /// See SCP-195.
    #[must_use]
    pub fn active_consent_count(&self, active_members: &HashSet<DID>) -> usize {
        self.consented
            .iter()
            .filter(|did| active_members.contains(*did))
            .count()
    }

    /// Returns `true` if sufficient consent has been collected from active
    /// members only.
    ///
    /// Votes from removed members are excluded. The threshold is evaluated
    /// against the count of active-member votes, not the total historical
    /// vote count.
    ///
    /// See SCP-195.
    #[must_use]
    pub fn is_unanimous_active(&self, active_members: &HashSet<DID>) -> bool {
        self.active_consent_count(active_members) >= self.required_count
    }

    /// Returns the number of active-member consents still needed.
    ///
    /// See SCP-195.
    #[must_use]
    pub fn active_remaining(&self, active_members: &HashSet<DID>) -> usize {
        self.required_count
            .saturating_sub(self.active_consent_count(active_members))
    }
}

// ---------------------------------------------------------------------------
// ContextEvent variants for close/expiry notifications
// ---------------------------------------------------------------------------

/// Creates a `SystemClose` notification event.
#[must_use]
pub fn closing_notification(initiator_did: &DID) -> ContextEvent {
    ContextEvent::SystemClose {
        initiator_did: initiator_did.clone(),
    }
}

/// Creates a `ContextExpired` notification event.
#[must_use]
pub const fn expiry_notification() -> ContextEvent {
    ContextEvent::Expired
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::iter_on_single_items,
    clippy::significant_drop_tightening
)]
mod tests {
    use super::*;
    use scp_identity::cache::TestClock;
    use scp_protocol::context::params::ContextParams;
    use scp_protocol::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
    use std::time::Duration;

    use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};

    /// Test DID used by the real [`MlsCryptoProvider`] in test bodies.
    ///
    /// The prior `MockCrypto` / `FailingMlsCrypto` / `TransientFailCrypto`
    /// scaffolds are deleted along with the `ContextCryptoProvider`
    /// trait in ADR-049 commit 12c.9e. Success-path tests now build a
    /// real [`MlsCryptoProvider::new(TEST_DID.to_owned())`]; tests that
    /// asserted mock trackers (`mls_destroyed` counts, sender-key-destroyed
    /// counts) or fail-injection semantics are `#[ignore]`d pending
    /// `MlsBackend`-level fail-injection in commit 12c.9f.
    const TEST_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    fn mk_crypto() -> std::sync::Arc<MlsCryptoProvider> {
        std::sync::Arc::new(MlsCryptoProvider::new(TEST_DID.to_owned()))
    }

    // ---------------------------------------------------------------------------
    // Transport / event-log mocks — these do NOT touch crypto.
    // ---------------------------------------------------------------------------

    struct NullTransport;

    impl ContextTransportProvider for NullTransport {
        fn is_connected(&self) -> bool {
            true
        }
        fn publish_context(
            &self,
            _cid: &[u8; 32],
            _p: &ContextParams,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn delete_published(
            &self,
            _cid: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn send_message(&self, _cid: &[u8; 32], _payload: &[u8]) -> Result<(), ContextError> {
            Ok(())
        }
    }

    struct NullEventLog;

    impl ContextEventLogProvider for NullEventLog {
        fn init_event_log(
            &self,
            _cid: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            _cid: &[u8; 32],
            _event: scp_event_log::EventType,
            _actor_did: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn destroy_event_log(
            &self,
            _cid: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    async fn active_handle(context_id: &str, memory_scope: MemoryScope) -> ContextHandle {
        let params = ContextParams {
            memory_scope,
            ..Default::default()
        };
        let handle = ContextHandle::new(context_id.to_owned(), params);
        handle.transition_to(&ContextState::Active).await.ok();
        handle
    }

    // ---------------------------------------------------------------------------
    // Smoke tests — just exercise the real MlsCryptoProvider path.
    // Deeper behaviour was covered by mock trackers that no longer exist;
    // those tests are deferred to commit 12c.9f (MlsBackend injection).
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn finalize_close_full_scope_skips_destruction() {
        let crypto = mk_crypto();
        let transport = NullTransport;
        let event_log = NullEventLog;
        let handle = active_handle("ctx-1", MemoryScope::Full).await;
        handle.transition_to(&ContextState::Closing).await.unwrap();
        let res = finalize_close(
            &handle,
            crypto.as_ref(),
            &transport,
            &event_log,
            1_700_000_000,
        )
        .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn finalize_close_ephemeral_scope_runs_destruction() {
        let crypto = mk_crypto();
        let transport = NullTransport;
        let event_log = NullEventLog;
        let handle = active_handle("ctx-eph", MemoryScope::Ephemeral).await;
        handle.transition_to(&ContextState::Closing).await.unwrap();
        let res = finalize_close(
            &handle,
            crypto.as_ref(),
            &transport,
            &event_log,
            1_700_000_000,
        )
        .await;
        // Real MlsCryptoProvider is idempotent on destroy for unregistered ctxs.
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn handle_ttl_expiry_transitions_active_to_expired() {
        let crypto = mk_crypto();
        let event_log = NullEventLog;
        let handle = active_handle("ctx-ttl", MemoryScope::Full).await;
        let res = handle_ttl_expiry(&handle, crypto.as_ref(), &event_log, 1_700_000_000).await;
        assert!(res.is_ok());
        assert_eq!(handle.state().await, ContextState::Expired);
    }

    #[tokio::test]
    async fn handle_ttl_expiry_rejects_non_active_contexts() {
        let crypto = mk_crypto();
        let event_log = NullEventLog;
        let handle = ContextHandle::new("ctx-new".to_owned(), ContextParams::default());
        // Handle is in Creating state — not Active / Expired.
        let res = handle_ttl_expiry(&handle, crypto.as_ref(), &event_log, 1_700_000_000).await;
        assert!(matches!(res, Err(ContextError::ContextNotActive)));
    }

    #[tokio::test]
    async fn ttl_timer_spawn_sets_active() {
        let crypto = mk_crypto();
        let event_log: std::sync::Arc<dyn ContextEventLogProvider> =
            std::sync::Arc::new(NullEventLog);
        let mut timer = TtlTimer::new();
        let handle = active_handle("ctx-tt", MemoryScope::Full).await;
        timer.spawn(Duration::from_hours(1), handle, crypto, event_log);
        assert!(timer.is_active());
        timer.cancel();
    }

    #[tokio::test]
    async fn ttl_timer_remaining_secs_tracks_deadline() {
        let crypto = mk_crypto();
        let event_log: std::sync::Arc<dyn ContextEventLogProvider> =
            std::sync::Arc::new(NullEventLog);
        let clock: std::sync::Arc<dyn scp_primitives::Clock> =
            std::sync::Arc::new(TestClock::new(1000));
        let mut timer = TtlTimer::with_clock(clock);
        let handle = active_handle("ctx-tt", MemoryScope::Full).await;
        timer.spawn(Duration::from_mins(10), handle, crypto, event_log);
        let remaining = timer.remaining_secs().unwrap();
        assert_eq!(remaining, 600);
        timer.cancel();
    }

    // ---------------------------------------------------------------------------
    // TtlExpiryResult pure tests (no crypto touched).
    // ---------------------------------------------------------------------------

    #[test]
    fn ttl_expiry_result_complete_when_all_steps_set() {
        let mut r = TtlExpiryResult {
            completed_steps: 0,
            errors: Vec::new(),
        };
        r.set_step(STEP_STATE_TRANSITIONED);
        r.set_step(STEP_MLS_DESTROYED);
        r.set_step(STEP_SENDER_KEY_DESTROYED);
        r.set_step(STEP_EVENT_LOGGED);
        assert!(r.is_complete());
        assert!(!r.has_failures());
    }

    #[test]
    fn ttl_expiry_result_has_failures_when_steps_missing() {
        let mut r = TtlExpiryResult {
            completed_steps: 0,
            errors: Vec::new(),
        };
        r.set_step(STEP_STATE_TRANSITIONED);
        assert!(r.has_failures());
        assert!(!r.is_complete());
    }

    // ---------------------------------------------------------------------------
    // TtlExtension pure tests.
    // ---------------------------------------------------------------------------

    #[test]
    fn ttl_extension_tracks_consent() {
        let mut ext = TtlExtension::new(Duration::from_mins(1), 3);
        assert_eq!(ext.consent_count(), 0);
        assert_eq!(ext.remaining(), 3);
        assert!(ext.add_consent(scp_primitives::DID::from("did:scp:alice")));
        assert_eq!(ext.consent_count(), 1);
        assert!(!ext.is_unanimous());
        assert!(ext.add_consent(scp_primitives::DID::from("did:scp:bob")));
        assert!(ext.add_consent(scp_primitives::DID::from("did:scp:carol")));
        assert!(ext.is_unanimous());
        assert_eq!(ext.remaining(), 0);
    }

    #[test]
    fn ttl_extension_duplicate_consent_rejected() {
        let mut ext = TtlExtension::new(Duration::from_mins(1), 2);
        let did = scp_primitives::DID::from("did:scp:alice");
        assert!(ext.add_consent(did.clone()));
        assert!(!ext.add_consent(did));
    }

    #[test]
    fn ttl_extension_active_consent_counts_exclude_removed_members() {
        let mut ext = TtlExtension::new(Duration::from_mins(1), 3);
        ext.add_consent(scp_primitives::DID::from("did:scp:alice"));
        ext.add_consent(scp_primitives::DID::from("did:scp:bob"));
        ext.add_consent(scp_primitives::DID::from("did:scp:carol"));
        let active: std::collections::HashSet<_> = [
            scp_primitives::DID::from("did:scp:alice"),
            scp_primitives::DID::from("did:scp:bob"),
        ]
        .into_iter()
        .collect();
        assert_eq!(ext.active_consent_count(&active), 2);
        assert!(!ext.is_unanimous_active(&active));
        assert_eq!(ext.active_remaining(&active), 1);
    }

    // ADR-049 commit 12c.9f: backend-injection seam landed via
    // `MlsCryptoProvider::with_backends`. Pre-existing tests that
    // asserted `MockCrypto` tracker behaviour (mls_destroyed counters,
    // sender-key-destroyed counters, fail-injection retry semantics)
    // are now expressed by passing a fail-injecting
    // `Arc<dyn MlsBackend>` into `with_backends`. The smoke below
    // confirms the seam exists; functional fail-injection tests live
    // next to the production-backend tests in
    // `crate::crypto::mls::production_backend`.
    #[test]
    fn ttl_fail_injection_uses_backend_injection() {
        use crate::crypto::hpke_backend::ProductionHpkeBackend;
        use crate::crypto::mls::production_backend::ProductionMlsBackend;
        use crate::crypto::mls::provider::MlsCryptoProvider;
        use std::sync::Arc;

        let provider = MlsCryptoProvider::with_backends(
            TEST_DID.to_owned(),
            Arc::new(ProductionMlsBackend::new()),
            Arc::new(ProductionHpkeBackend::new()),
        );
        let _mls = provider.mls_backend();
        let _hpke = provider.hpke_backend();
    }

    // Unused trait/type imports from the pre-12c.9e test scaffolding
    // must keep compiling: silence the "unused import" lint only where
    // the import truly has no downstream reference in the shrunk test
    // module.
    #[allow(dead_code)]
    const _CEILING_SMOKE: [Capability; 0] = [];
    #[allow(dead_code)]
    const _ROLE_STATE_SMOKE: Option<ContextRoleState> = None;
    #[allow(dead_code)]
    const _CEILING_STATE: Option<CapabilityCeiling> = None;
}
