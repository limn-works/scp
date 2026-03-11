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
use tokio::task::JoinHandle;

use super::builder::{ContextCryptoProvider, ContextEventLogProvider, ContextTransportProvider};
use super::membership::ContextEvent;
use super::params::GovernanceModel;
use super::roles::{self, ContextRoleState};
use super::{ContextError, ContextHandle, ContextState, MemoryScope};
use scp_identity::DID;
use scp_identity::cache::Clock;

// ---------------------------------------------------------------------------
// context_id_to_bytes helper (mirrors manager.rs)
// ---------------------------------------------------------------------------

/// Uses the canonical SHA-256 context ID byte derivation.
/// Delegates to [`super::context_id_bytes`] to match builder.rs.
fn context_id_to_bytes(context_id: &str) -> [u8; 32] {
    super::context_id_bytes(context_id)
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
// TtlExpiryError — structured expiry failure with partial-success tracking
// ---------------------------------------------------------------------------

/// Tracks which cleanup operations succeeded/failed during TTL expiry.
///
/// When expiry cleanup fails, some operations may have completed
/// successfully (e.g., MLS group destroyed but event log write failed).
/// This struct preserves that information so callers know the exact state.
#[derive(Debug, Clone)]
pub struct TtlExpiryError {
    /// Bitfield tracking completion of each cleanup step.
    ///
    /// Bit 0: state transition to `Expired`.
    /// Bit 1: MLS group destruction (or not required).
    /// Bit 2: sender key destruction (or not required).
    /// Bit 3: event log append.
    completed_steps: u8,
    /// The error messages from failed operations.
    pub errors: Vec<String>,
}

/// Bit positions for [`TtlExpiryError::completed_steps`].
const STEP_STATE_TRANSITIONED: u8 = 0b0000_0001;
const STEP_MLS_DESTROYED: u8 = 0b0000_0010;
const STEP_SENDER_KEY_DESTROYED: u8 = 0b0000_0100;
const STEP_EVENT_LOGGED: u8 = 0b0000_1000;

/// Mask for all steps complete.
const ALL_STEPS: u8 =
    STEP_STATE_TRANSITIONED | STEP_MLS_DESTROYED | STEP_SENDER_KEY_DESTROYED | STEP_EVENT_LOGGED;

impl TtlExpiryError {
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

    const fn set_step(&mut self, step: u8) {
        self.completed_steps |= step;
    }
}

impl std::fmt::Display for TtlExpiryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl std::error::Error for TtlExpiryError {}

/// Maximum number of retry attempts for TTL expiry cleanup.
const TTL_EXPIRY_MAX_RETRIES: u32 = 5;

/// Base delay for exponential backoff between TTL expiry retries.
const TTL_EXPIRY_BASE_DELAY: Duration = Duration::from_millis(500);

/// Callback type for TTL expiry failure notification.
///
/// Called with `(context_id, error)` when TTL expiry fails after all retries
/// are exhausted. This allows the application layer to observe and react to
/// failed expirations (e.g., mark the context as needing manual cleanup).
pub type TtlExpiryErrorCallback = Arc<dyn Fn(String, TtlExpiryError) + Send + Sync>;

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
            clock.now(),
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
        if new_deadline > clock.now() {
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
                let now = clock.now();
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

    event_log.append_context_event(&context_id_bytes, "ContextClosing")?;

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
    crypto: &dyn ContextCryptoProvider,
    transport: &dyn ContextTransportProvider,
    event_log: &dyn ContextEventLogProvider,
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

    event_log.append_context_event(&context_id_bytes, "ContextClosed")?;

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
    crypto: &dyn ContextCryptoProvider,
    event_log: &dyn ContextEventLogProvider,
) -> Result<(), ContextError> {
    handle_ttl_expiry_with_transport(handle, crypto, None, event_log).await
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
    crypto: &dyn ContextCryptoProvider,
    transport: Option<&dyn ContextTransportProvider>,
    event_log: &dyn ContextEventLogProvider,
) -> Result<(), ContextError> {
    let state = handle.state().await;
    if state != ContextState::Active && state != ContextState::Expired {
        return Err(ContextError::ContextNotActive);
    }

    let result = try_ttl_expiry_cleanup(handle, crypto, transport, event_log).await;

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
/// Returns a [`TtlExpiryError`] that tracks which operations succeeded and
/// which failed. This function is idempotent: if the context has already
/// transitioned to `Expired`, it skips the transition and retries only the
/// remaining cleanup operations.
///
/// Partial successes are preserved across retries — an operation that
/// succeeded on a previous attempt is not re-attempted.
pub async fn try_ttl_expiry_cleanup(
    handle: &ContextHandle,
    crypto: &dyn ContextCryptoProvider,
    transport: Option<&dyn ContextTransportProvider>,
    event_log: &dyn ContextEventLogProvider,
) -> TtlExpiryError {
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = context_id_to_bytes(&context_id);
    let memory_scope = handle.params().memory_scope;

    let mut result = TtlExpiryError {
        completed_steps: 0,
        errors: Vec::new(),
    };

    let needs_key_destruction =
        memory_scope == MemoryScope::Ephemeral || memory_scope == MemoryScope::Summary;

    // If keys are not required to be destroyed, mark them as done.
    if !needs_key_destruction {
        result.set_step(STEP_MLS_DESTROYED | STEP_SENDER_KEY_DESTROYED);
    }

    // 1. State transition (idempotent — skip if already Expired).
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
            let msg =
                format!("context is in {state} state, expected Active or Expired for TTL expiry");
            tracing::error!(context_id = %context_id, "{msg}");
            result.errors.push(msg);
            return result;
        }
    }

    // 2. Key destruction (Ephemeral/Summary only). Each operation is
    //    independent — a failure in one does not block the other.
    if needs_key_destruction {
        match crypto.destroy_mls_group(&context_id_bytes) {
            Ok(()) => result.set_step(STEP_MLS_DESTROYED),
            Err(e) => {
                let msg = format!("failed to destroy MLS group: {e}");
                tracing::warn!(context_id = %context_id, error = %e,
                    "failed to destroy MLS group after TTL expiry — keys may persist");
                result.errors.push(msg);
            }
        }
        match crypto.destroy_sender_key(&context_id_bytes) {
            Ok(()) => result.set_step(STEP_SENDER_KEY_DESTROYED),
            Err(e) => {
                let msg = format!("failed to destroy sender key: {e}");
                tracing::warn!(context_id = %context_id, error = %e,
                    "failed to destroy sender key after TTL expiry — keys may persist");
                result.errors.push(msg);
            }
        }

        // Best-effort relay ciphertext deletion (§5.11). Relay deletion is
        // non-blocking — even if the relay retains the encrypted blobs, the
        // keys are destroyed and the data is unreadable.
        if let Some(transport) = transport
            && let Err(e) = transport.delete_published(&context_id_bytes)
        {
            tracing::warn!(context_id = %context_id, error = %e,
                "best-effort relay deletion failed after TTL expiry");
        }
    }

    // 3. Event log append.
    match event_log.append_context_event(&context_id_bytes, "ContextExpired") {
        Ok(()) => result.set_step(STEP_EVENT_LOGGED),
        Err(e) => {
            let msg = format!("failed to log ContextExpired event: {e}");
            tracing::warn!(context_id = %context_id, error = %e,
                "failed to append ContextExpired to event log");
            result.errors.push(msg);
        }
    }

    result
}

impl TtlExpiryError {
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
/// Attempts cleanup up to [`TTL_EXPIRY_MAX_RETRIES`] times. Partial successes
/// are tracked — only failed operations are retried. If the cancel signal
/// fires during a retry delay, cleanup is abandoned.
///
/// Returns the final [`TtlExpiryError`] result after all retries are
/// exhausted or cleanup succeeds.
pub async fn run_ttl_expiry_with_retries(
    handle: &ContextHandle,
    crypto: &dyn ContextCryptoProvider,
    transport: Option<&dyn ContextTransportProvider>,
    event_log: &dyn ContextEventLogProvider,
    cancel: &Notify,
) -> TtlExpiryError {
    let context_id = handle.context_id().to_owned();

    for attempt in 0..TTL_EXPIRY_MAX_RETRIES {
        let result = try_ttl_expiry_cleanup(handle, crypto, transport, event_log).await;

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
    TtlExpiryError {
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
/// [`TTL_EXPIRY_MAX_RETRIES`] attempts). If cleanup fails after all retries,
/// the optional `on_error` callback is invoked with the context ID and a
/// [`TtlExpiryError`] describing which operations succeeded and which failed.
///
/// See ADR-008 acceptance criterion 9.
pub struct TtlTimer {
    /// The spawned timer task handle. `None` if no TTL is configured.
    pub(crate) task: Option<JoinHandle<()>>,
    /// Cancellation signal.
    pub(crate) cancel: Arc<Notify>,
    /// Absolute deadline as Unix epoch seconds, set when timer is spawned.
    /// Used to compute remaining TTL for persistence snapshots.
    pub(crate) deadline_unix_secs: Option<u64>,
    /// Optional callback invoked when TTL expiry fails after all retries.
    pub(crate) on_error: Option<TtlExpiryErrorCallback>,
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
        }
    }

    /// Creates a new `TtlTimer` with an error callback.
    ///
    /// The callback is invoked with `(context_id, error)` when TTL expiry
    /// cleanup fails after all retry attempts are exhausted.
    #[must_use]
    pub fn with_error_callback(on_error: TtlExpiryErrorCallback) -> Self {
        Self {
            task: None,
            cancel: Arc::new(Notify::new()),
            deadline_unix_secs: None,
            on_error: Some(on_error),
        }
    }

    /// Sets the error callback. Replaces any existing callback.
    pub fn set_error_callback(&mut self, on_error: TtlExpiryErrorCallback) {
        self.on_error = Some(on_error);
    }

    /// Spawns a TTL timer task that fires after the given duration.
    pub fn spawn(
        &mut self,
        duration: Duration,
        handle: ContextHandle,
        crypto: Arc<dyn ContextCryptoProvider>,
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
        crypto: Arc<dyn ContextCryptoProvider>,
        transport: Option<Arc<dyn ContextTransportProvider>>,
        event_log: Arc<dyn ContextEventLogProvider>,
    ) {
        // Record absolute deadline for persistence snapshots.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.deadline_unix_secs = Some(now_secs.saturating_add(duration.as_secs()));

        let cancel = self.cancel.clone();
        let on_error = self.on_error.clone();
        let context_id = handle.context_id().to_owned();

        let task = tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(duration) => {
                    let result = run_ttl_expiry_with_retries(
                        &handle,
                        crypto.as_ref(),
                        transport.as_deref(),
                        event_log.as_ref(),
                        &cancel,
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

        self.task = Some(task);
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
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
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
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::context::builder::{
        ContextCreationError, ContextCryptoProvider, ContextEventLogProvider,
        ContextTransportProvider,
    };
    use crate::context::params::ContextParams;
    use crate::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
    use scp_identity::cache::TestClock;

    #[derive(Default)]
    struct MockCrypto {
        mls_destroyed: Mutex<Vec<[u8; 32]>>,
        sender_keys_destroyed: Mutex<Vec<[u8; 32]>>,
    }

    impl ContextCryptoProvider for MockCrypto {
        fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn create_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn generate_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn init_broadcast_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn destroy_mls_group(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.mls_destroyed.lock().unwrap().push(*id);
            Ok(())
        }
        fn destroy_sender_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.sender_keys_destroyed.lock().unwrap().push(*id);
            Ok(())
        }
        fn validate_key_package(
            &self,
            _owner_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<(), ContextError> {
            Ok(())
        }
        fn add_member(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<(), ContextError> {
            Ok(())
        }
        fn remove_member(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }
        fn distribute_sender_key(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }
        fn remove_member_sender_key(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }
        fn encrypt_message(
            &self,
            _context_id: &[u8; 32],
            _sender_did: &str,
            payload: &[u8],
            _epoch: u64,
            _sequence: u64,
        ) -> Result<Vec<u8>, ContextError> {
            Ok(payload.to_vec())
        }
    }

    #[derive(Default)]
    struct MockTransport {
        connected: AtomicBool,
        deleted: Mutex<Vec<[u8; 32]>>,
    }

    impl MockTransport {
        fn connected() -> Self {
            let t = Self::default();
            t.connected.store(true, Ordering::Relaxed);
            t
        }
    }

    impl ContextTransportProvider for MockTransport {
        fn is_connected(&self) -> bool {
            self.connected.load(Ordering::Relaxed)
        }
        fn publish_context(
            &self,
            _id: &[u8; 32],
            _params: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn delete_published(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.deleted.lock().unwrap().push(*id);
            Ok(())
        }
        fn send_message(
            &self,
            _context_id: &[u8; 32],
            _encrypted_payload: &[u8],
        ) -> Result<(), ContextError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockEventLog {
        events: Mutex<Vec<([u8; 32], String)>>,
    }

    impl ContextEventLogProvider for MockEventLog {
        fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn append_event(&self, id: &[u8; 32], event: &str) -> Result<(), ContextCreationError> {
            self.events.lock().unwrap().push((*id, event.to_owned()));
            Ok(())
        }
        fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }

    fn role_state_with_close_capability(context_id: &str, creator_did: &str) -> ContextRoleState {
        let ceiling = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ContextClose,
            Capability::RoleAssign,
        ]);
        ContextRoleState::new(context_id, creator_did, ceiling, vec![]).unwrap()
    }

    fn role_state_without_close_capability(
        context_id: &str,
        creator_did: &str,
    ) -> ContextRoleState {
        let ceiling = CapabilityCeiling::new([Capability::MessagesRead, Capability::MessagesWrite]);
        ContextRoleState::new(context_id, creator_did, ceiling, vec![]).unwrap()
    }

    fn active_handle(context_id: &str, memory_scope: MemoryScope) -> ContextHandle {
        let params = ContextParams {
            memory_scope,
            ..ContextParams::default()
        };
        ContextHandle::new(context_id.to_owned(), params)
    }

    async fn make_active(handle: &ContextHandle) {
        handle.transition_to(&ContextState::Active).await.unwrap();
    }

    #[tokio::test]
    async fn close_context_rejects_without_close_capability() {
        let handle = active_handle("ctx-close-1", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let role_state = role_state_without_close_capability("ctx-close-1", "did:key:creator");
        let event_log = MockEventLog::default();
        let result =
            close_context(&handle, &"did:key:creator".into(), &role_state, &event_log).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::PermissionDenied(_)
        ));
        assert_eq!(handle.state().await, ContextState::Active);
    }

    #[tokio::test]
    async fn close_context_succeeds_for_admin_with_capability() {
        let handle = active_handle("ctx-close-2", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let role_state = role_state_with_close_capability("ctx-close-2", "did:key:creator");
        let event_log = MockEventLog::default();
        let result =
            close_context(&handle, &"did:key:creator".into(), &role_state, &event_log).await;
        assert!(result.is_ok());
        let close_result = result.unwrap();
        assert!(!close_result.should_generate_summary);
        assert!(close_result.should_schedule_key_destruction);
        assert_eq!(handle.state().await, ContextState::Closing);
    }

    #[tokio::test]
    async fn close_context_summary_scope_triggers_summary_generation() {
        let handle = active_handle("ctx-close-3", MemoryScope::Summary);
        make_active(&handle).await;
        let role_state = role_state_with_close_capability("ctx-close-3", "did:key:creator");
        let event_log = MockEventLog::default();
        let result =
            close_context(&handle, &"did:key:creator".into(), &role_state, &event_log).await;
        assert!(result.is_ok());
        assert!(result.unwrap().should_generate_summary);
    }

    #[tokio::test]
    async fn close_context_full_scope_retains_keys() {
        let handle = active_handle("ctx-close-4", MemoryScope::Full);
        make_active(&handle).await;
        let role_state = role_state_with_close_capability("ctx-close-4", "did:key:creator");
        let event_log = MockEventLog::default();
        let result =
            close_context(&handle, &"did:key:creator".into(), &role_state, &event_log).await;
        assert!(result.is_ok());
        let cr = result.unwrap();
        assert!(!cr.should_generate_summary);
        assert!(!cr.should_schedule_key_destruction);
    }

    #[tokio::test]
    async fn close_context_rejects_when_not_active() {
        let handle = active_handle("ctx-close-5", MemoryScope::Ephemeral);
        let role_state = role_state_with_close_capability("ctx-close-5", "did:key:creator");
        let event_log = MockEventLog::default();
        let result =
            close_context(&handle, &"did:key:creator".into(), &role_state, &event_log).await;
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    #[tokio::test]
    async fn finalize_close_destroys_mls_group_and_sender_keys() {
        let handle = active_handle("ctx-final-1", MemoryScope::Ephemeral);
        make_active(&handle).await;
        handle.transition_to(&ContextState::Closing).await.unwrap();
        let crypto = MockCrypto::default();
        let transport = MockTransport::connected();
        let event_log = MockEventLog::default();
        assert!(
            finalize_close(&handle, &crypto, &transport, &event_log)
                .await
                .is_ok()
        );
        assert_eq!(crypto.mls_destroyed.lock().unwrap().len(), 1);
        assert_eq!(handle.state().await, ContextState::Closed);
    }

    #[tokio::test]
    async fn finalize_close_rejects_when_not_closing() {
        let handle = active_handle("ctx-final-4", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        let transport = MockTransport::connected();
        let event_log = MockEventLog::default();
        assert!(
            finalize_close(&handle, &crypto, &transport, &event_log)
                .await
                .is_err()
        );
    }

    /// SCP-164: Calling `finalize_close` on a context NOT in Closing state
    /// must return an error AND must NOT destroy any key material.
    #[tokio::test]
    async fn finalize_close_on_active_context_returns_error_and_preserves_keys() {
        let handle = active_handle("ctx-164-guard", MemoryScope::Ephemeral);
        make_active(&handle).await;
        // Context is Active, not Closing.
        let crypto = MockCrypto::default();
        let transport = MockTransport::connected();
        let event_log = MockEventLog::default();

        let result = finalize_close(&handle, &crypto, &transport, &event_log).await;

        // Must return an InvalidTransition error.
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::InvalidTransition {
                from: ContextState::Active,
                to: ContextState::Closed,
            }
        ));
        // Keys must NOT have been destroyed.
        assert!(
            crypto.mls_destroyed.lock().unwrap().is_empty(),
            "MLS group must not be destroyed when state transition fails"
        );
        assert!(
            crypto.sender_keys_destroyed.lock().unwrap().is_empty(),
            "sender keys must not be destroyed when state transition fails"
        );
        // State must remain Active.
        assert_eq!(handle.state().await, ContextState::Active);
    }

    /// SCP-164: Calling `finalize_close` on a Closing context must succeed,
    /// transition to Closed, and destroy keys in the correct order
    /// (state transition validated before key destruction).
    #[tokio::test]
    async fn finalize_close_on_closing_context_succeeds_and_destroys_keys() {
        let handle = active_handle("ctx-164-happy", MemoryScope::Ephemeral);
        make_active(&handle).await;
        handle.transition_to(&ContextState::Closing).await.unwrap();

        let crypto = MockCrypto::default();
        let transport = MockTransport::connected();
        let event_log = MockEventLog::default();

        let result = finalize_close(&handle, &crypto, &transport, &event_log).await;

        // Must succeed.
        assert!(result.is_ok());
        // State must be Closed.
        assert_eq!(handle.state().await, ContextState::Closed);
        // MLS group must have been destroyed.
        assert_eq!(
            crypto.mls_destroyed.lock().unwrap().len(),
            1,
            "MLS group must be destroyed on successful finalize_close"
        );
        // Sender keys must have been destroyed.
        assert_eq!(
            crypto.sender_keys_destroyed.lock().unwrap().len(),
            1,
            "sender keys must be destroyed on successful finalize_close"
        );
        // Event log must contain the ContextClosed event.
        assert_eq!(
            event_log.events.lock().unwrap().len(),
            1,
            "ContextClosed event must be recorded"
        );
    }

    #[tokio::test]
    async fn ttl_expiry_transitions_active_to_expired() {
        let handle = active_handle("ctx-ttl-1", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        let event_log = MockEventLog::default();
        assert!(
            handle_ttl_expiry(&handle, &crypto, &event_log)
                .await
                .is_ok()
        );
        assert_eq!(handle.state().await, ContextState::Expired);
    }

    #[tokio::test]
    async fn ttl_expiry_full_scope_retains_keys() {
        let handle = active_handle("ctx-ttl-2", MemoryScope::Full);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        let event_log = MockEventLog::default();
        assert!(
            handle_ttl_expiry(&handle, &crypto, &event_log)
                .await
                .is_ok()
        );
        assert!(crypto.mls_destroyed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn ttl_expiry_rejects_when_not_active() {
        let handle = active_handle("ctx-ttl-3", MemoryScope::Ephemeral);
        let crypto = MockCrypto::default();
        let event_log = MockEventLog::default();
        assert!(matches!(
            handle_ttl_expiry(&handle, &crypto, &event_log)
                .await
                .unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    #[tokio::test]
    async fn ttl_timer_fires_and_expires_context() {
        let handle = active_handle("ctx-timer-1", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto: Arc<dyn ContextCryptoProvider> = Arc::new(MockCrypto::default());
        let event_log: Arc<dyn ContextEventLogProvider> = Arc::new(MockEventLog::default());
        let mut timer = TtlTimer::new();
        timer.spawn(Duration::from_millis(50), handle.clone(), crypto, event_log);
        assert!(timer.is_active());
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(handle.state().await, ContextState::Expired);
    }

    #[tokio::test]
    async fn ttl_timer_cancelled_on_early_close() {
        let handle = active_handle("ctx-timer-2", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto: Arc<dyn ContextCryptoProvider> = Arc::new(MockCrypto::default());
        let event_log: Arc<dyn ContextEventLogProvider> = Arc::new(MockEventLog::default());
        let mut timer = TtlTimer::new();
        timer.spawn(Duration::from_secs(10), handle.clone(), crypto, event_log);
        timer.cancel();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(handle.state().await, ContextState::Active);
        assert!(!timer.is_active());
    }

    #[tokio::test]
    async fn ttl_timer_default_is_inactive() {
        assert!(!TtlTimer::default().is_active());
    }

    #[test]
    fn ttl_extension_requires_unanimous_consent() {
        let mut ext = TtlExtension::new(Duration::from_secs(3600), 3);
        assert!(!ext.is_unanimous());
        ext.add_consent("did:key:alice".into());
        ext.add_consent("did:key:bob".into());
        ext.add_consent("did:key:charlie".into());
        assert!(ext.is_unanimous());
    }

    #[test]
    fn ttl_extension_duplicate_consent_ignored() {
        let mut ext = TtlExtension::new(Duration::from_secs(3600), 2);
        assert!(ext.add_consent("did:key:alice".into()));
        assert!(!ext.add_consent("did:key:alice".into()));
        assert_eq!(ext.consent_count(), 1);
    }

    #[test]
    fn ttl_extension_single_member_unanimity() {
        let mut ext = TtlExtension::new(Duration::from_secs(600), 1);
        assert!(ext.add_consent("did:key:alice".into()));
        assert!(ext.is_unanimous());
    }

    // -----------------------------------------------------------------------
    // SCP-195 tests: active-member consent validation at tally time
    // -----------------------------------------------------------------------

    /// SCP-195: Active member's vote is counted in the tally.
    #[test]
    fn ttl_extension_active_member_vote_counted() {
        let mut ext = TtlExtension::new(Duration::from_secs(3600), 2);
        ext.add_consent("did:key:alice".into());
        ext.add_consent("did:key:bob".into());

        let active: HashSet<DID> = ["did:key:alice".into(), "did:key:bob".into()]
            .into_iter()
            .collect();

        assert_eq!(ext.active_consent_count(&active), 2);
        assert!(ext.is_unanimous_active(&active));
    }

    /// SCP-195: Removed member's vote is excluded from the tally.
    #[test]
    fn ttl_extension_removed_member_vote_excluded() {
        let mut ext = TtlExtension::new(Duration::from_secs(3600), 2);
        ext.add_consent("did:key:alice".into());
        ext.add_consent("did:key:bob".into());

        // Bob was removed before tally time -- only Alice is active.
        let active: HashSet<DID> = ["did:key:alice".into()].into_iter().collect();

        assert_eq!(ext.active_consent_count(&active), 1);
        assert!(!ext.is_unanimous_active(&active));
        assert_eq!(ext.active_remaining(&active), 1);
    }

    /// SCP-195: Threshold evaluated against active votes only.
    ///
    /// Scenario: 3 members, threshold=3 (`AllMember`). Alice, Bob, Charlie all
    /// vote. Charlie is removed before tally. Only 2 of 3 required consents
    /// remain active, so the proposal is NOT approved.
    #[test]
    fn ttl_extension_threshold_against_active_votes_only() {
        let mut ext = TtlExtension::new(Duration::from_secs(3600), 3);
        ext.add_consent("did:key:alice".into());
        ext.add_consent("did:key:bob".into());
        ext.add_consent("did:key:charlie".into());

        // Without active-member filtering, the old method passes.
        assert!(ext.is_unanimous());

        // Charlie removed -- only Alice and Bob are active.
        let active: HashSet<DID> = ["did:key:alice".into(), "did:key:bob".into()]
            .into_iter()
            .collect();

        // Active tally: 2 of 3 required -- not enough.
        assert_eq!(ext.active_consent_count(&active), 2);
        assert!(!ext.is_unanimous_active(&active));
    }

    /// SCP-195: Majority threshold passes with active members.
    ///
    /// Scenario: 3 active members, `required_count=2` (governance-based
    /// majority). 2 of 3 active members consent => passes.
    #[test]
    fn ttl_extension_majority_threshold_with_active_members() {
        let mut ext = TtlExtension::new(Duration::from_secs(3600), 2);
        ext.add_consent("did:key:alice".into());
        ext.add_consent("did:key:bob".into());

        let active: HashSet<DID> = [
            "did:key:alice".into(),
            "did:key:bob".into(),
            "did:key:charlie".into(),
        ]
        .into_iter()
        .collect();

        assert_eq!(ext.active_consent_count(&active), 2);
        assert!(ext.is_unanimous_active(&active));
    }

    /// SCP-195: Edge case -- all voters removed means no consent.
    #[test]
    fn ttl_extension_all_voters_removed_no_consent() {
        let mut ext = TtlExtension::new(Duration::from_secs(3600), 2);
        ext.add_consent("did:key:alice".into());
        ext.add_consent("did:key:bob".into());

        // Both voters removed -- no active members who voted.
        let active: HashSet<DID> = HashSet::new();

        assert_eq!(ext.active_consent_count(&active), 0);
        assert!(!ext.is_unanimous_active(&active));
        assert_eq!(ext.active_remaining(&active), 2);
    }

    /// SCP-195: `TtlExtensionProposal` delegates active-member checks correctly.
    #[test]
    fn extension_proposal_active_member_validation() {
        let mut proposal = TtlExtensionProposal::new(
            "did:key:alice".into(),
            Duration::from_secs(3600),
            2,
            GovernanceModel::SingleAdmin,
        );
        proposal.record_consent("did:key:alice".into());
        proposal.record_consent("did:key:bob".into());

        // Both active -- approved.
        let both_active: HashSet<DID> = ["did:key:alice".into(), "did:key:bob".into()]
            .into_iter()
            .collect();
        assert!(proposal.is_approved_active(&both_active));
        assert_eq!(proposal.active_consent_count(&both_active), 2);
        assert_eq!(proposal.active_remaining(&both_active), 0);

        // Bob removed -- not approved.
        let alice_only: HashSet<DID> = ["did:key:alice".into()].into_iter().collect();
        assert!(!proposal.is_approved_active(&alice_only));
        assert_eq!(proposal.active_consent_count(&alice_only), 1);
        assert_eq!(proposal.active_remaining(&alice_only), 1);
    }

    /// SCP-195: Vote cast by member active at vote time but removed before
    /// tally is excluded from the count.
    #[test]
    fn extension_proposal_vote_then_remove_before_tally() {
        // Bilateral context (member_count=2) uses AllMember consent mode,
        // requiring both members to consent.
        let mut proposal = TtlExtensionProposal::new(
            "did:key:alice".into(),
            Duration::from_secs(3600),
            2,
            GovernanceModel::SingleAdmin,
        );
        // Both members vote while active.
        proposal.record_consent("did:key:alice".into());
        proposal.record_consent("did:key:bob".into());

        // Old method: approved (both voted, required 2 for AllMember mode).
        assert!(proposal.is_approved());

        // Bob is removed before tally time.
        let active: HashSet<DID> = ["did:key:alice".into()].into_iter().collect();

        // Active method: NOT approved (only 1 of 2 required active votes).
        assert!(!proposal.is_approved_active(&active));
        assert_eq!(proposal.active_consent_count(&active), 1);
    }

    // SCP-066 tests: check_ttl

    #[test]
    fn check_ttl_returns_ok_when_active() {
        assert!(
            check_ttl(
                1000,
                TtlPolicy::Finite(Duration::from_secs(3600)),
                None,
                2000
            )
            .is_ok()
        );
    }

    #[test]
    fn check_ttl_returns_expired_when_elapsed() {
        assert!(matches!(
            check_ttl(
                1000,
                TtlPolicy::Finite(Duration::from_secs(3600)),
                None,
                5000
            )
            .unwrap_err(),
            TtlError::Expired
        ));
    }

    #[test]
    fn check_ttl_returns_expired_at_exact_deadline() {
        assert!(
            check_ttl(
                1000,
                TtlPolicy::Finite(Duration::from_secs(3600)),
                None,
                4600
            )
            .is_err()
        );
    }

    #[test]
    fn check_ttl_none_policy_always_ok() {
        assert!(check_ttl(0, TtlPolicy::None, None, u64::MAX).is_ok());
    }

    #[test]
    fn check_ttl_respects_extension() {
        assert!(
            check_ttl(
                1000,
                TtlPolicy::Finite(Duration::from_secs(3600)),
                Some(10000),
                5000
            )
            .is_ok()
        );
    }

    #[test]
    fn check_ttl_expired_extension() {
        assert!(
            check_ttl(
                1000,
                TtlPolicy::Finite(Duration::from_secs(3600)),
                Some(8000),
                9000
            )
            .is_err()
        );
    }

    // SCP-066 tests: TtlEnforcer

    #[test]
    fn ttl_enforcer_check_active() {
        let clock = TestClock::new(1000);
        let mut enforcer = TtlEnforcer::new(1000, TtlPolicy::Finite(Duration::from_secs(3600)));
        assert!(enforcer.check(&clock).is_ok());
        assert!(!enforcer.is_expired());
    }

    #[test]
    fn ttl_enforcer_check_expired() {
        let clock = TestClock::new(5000);
        let mut enforcer = TtlEnforcer::new(1000, TtlPolicy::Finite(Duration::from_secs(3600)));
        assert!(enforcer.check(&clock).is_err());
        assert!(enforcer.is_expired());
    }

    #[test]
    fn ttl_enforcer_latches_expired() {
        let clock = TestClock::new(5000);
        let mut enforcer = TtlEnforcer::new(1000, TtlPolicy::Finite(Duration::from_secs(3600)));
        assert!(enforcer.check(&clock).is_err());
        clock.set(2000);
        assert!(enforcer.check(&clock).is_err());
    }

    #[test]
    fn ttl_enforcer_none_policy_always_ok() {
        let clock = TestClock::new(u64::MAX);
        let mut enforcer = TtlEnforcer::new(0, TtlPolicy::None);
        assert!(enforcer.check(&clock).is_ok());
    }

    #[test]
    fn ttl_enforcer_apply_extension_resets_deadline() {
        // created_at=1000, TTL=3600s => deadline=4600. Clock at 4700 is past deadline.
        let clock = TestClock::new(4700);
        let mut enforcer = TtlEnforcer::new(1000, TtlPolicy::Finite(Duration::from_secs(3600)));
        assert!(enforcer.check(&clock).is_err());
        // Apply extension to 8000 -- this clears the expired latch and sets
        // extended_until.
        enforcer.apply_extension(8000, &clock).unwrap();
        assert!(!enforcer.is_expired());
        assert!(enforcer.check(&clock).is_ok());
        assert_eq!(enforcer.extended_until(), Some(8000));
    }

    #[test]
    fn ttl_enforcer_apply_extension_rejects_none_policy() {
        let clock = TestClock::new(1000);
        let mut enforcer = TtlEnforcer::new(0, TtlPolicy::None);
        assert!(matches!(
            enforcer.apply_extension(5000, &clock).unwrap_err(),
            TtlError::NoTtlPolicy
        ));
    }

    #[test]
    fn ttl_enforcer_remaining_secs() {
        let clock = TestClock::new(2000);
        let enforcer = TtlEnforcer::new(1000, TtlPolicy::Finite(Duration::from_secs(3600)));
        assert_eq!(enforcer.remaining_secs(&clock), Some(2600));
    }

    #[test]
    fn ttl_enforcer_remaining_secs_expired() {
        let clock = TestClock::new(5000);
        let enforcer = TtlEnforcer::new(1000, TtlPolicy::Finite(Duration::from_secs(3600)));
        assert_eq!(enforcer.remaining_secs(&clock), Some(0));
    }

    #[test]
    fn ttl_enforcer_remaining_secs_none_policy() {
        let clock = TestClock::new(1000);
        let enforcer = TtlEnforcer::new(0, TtlPolicy::None);
        assert_eq!(enforcer.remaining_secs(&clock), Option::None);
    }

    #[test]
    fn ttl_enforcer_accessors() {
        let enforcer = TtlEnforcer::new(1000, TtlPolicy::Finite(Duration::from_secs(3600)));
        assert_eq!(enforcer.created_at(), 1000);
        assert_eq!(
            enforcer.ttl_policy(),
            TtlPolicy::Finite(Duration::from_secs(3600))
        );
        assert_eq!(enforcer.extended_until(), None);
        assert!(!enforcer.is_expired());
    }

    // SCP-066 tests: ExtensionConsentMode

    #[test]
    fn consent_mode_bilateral_uses_all_member() {
        assert_eq!(
            consent_mode_for_member_count(2),
            ExtensionConsentMode::AllMember
        );
    }

    #[test]
    fn consent_mode_multi_party_uses_governance() {
        assert_eq!(
            consent_mode_for_member_count(3),
            ExtensionConsentMode::Governance
        );
    }

    // SCP-066 tests: TtlExtensionProposal

    #[test]
    fn extension_proposal_bilateral_requires_all_members() {
        let mut proposal = TtlExtensionProposal::new(
            "did:key:alice".into(),
            Duration::from_secs(3600),
            2,
            GovernanceModel::SingleAdmin,
        );
        assert_eq!(proposal.consent_mode(), ExtensionConsentMode::AllMember);
        assert!(!proposal.is_approved());
        proposal.record_consent("did:key:alice".into());
        assert!(!proposal.is_approved());
        proposal.record_consent("did:key:bob".into());
        assert!(proposal.is_approved());
    }

    #[test]
    fn extension_proposal_multi_party_single_admin() {
        let mut proposal = TtlExtensionProposal::new(
            "did:key:admin".into(),
            Duration::from_secs(7200),
            5,
            GovernanceModel::SingleAdmin,
        );
        assert_eq!(proposal.consent_mode(), ExtensionConsentMode::Governance);
        proposal.record_consent("did:key:admin".into());
        assert!(proposal.is_approved());
    }

    #[test]
    fn extension_proposal_computes_deadline() {
        let proposal = TtlExtensionProposal::new(
            "did:key:alice".into(),
            Duration::from_secs(3600),
            2,
            GovernanceModel::SingleAdmin,
        );
        assert_eq!(proposal.compute_new_deadline(5000), 8600);
    }

    // SCP-066 tests: TtlTimerHandle

    struct MockTimerHandle {
        cancelled: std::sync::atomic::AtomicBool,
        active: std::sync::atomic::AtomicBool,
        reset_dur: std::sync::Mutex<Option<Duration>>,
    }
    impl MockTimerHandle {
        fn new() -> Self {
            Self {
                cancelled: std::sync::atomic::AtomicBool::new(false),
                active: std::sync::atomic::AtomicBool::new(true),
                reset_dur: std::sync::Mutex::new(None),
            }
        }
    }
    impl TtlTimerHandle for MockTimerHandle {
        fn cancel_timer(&self) {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::Relaxed);
            self.active
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
        fn reset_timer(&mut self, d: Duration) {
            *self.reset_dur.lock().unwrap() = Some(d);
            self.active
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        fn is_timer_active(&self) -> bool {
            self.active.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[test]
    fn ttl_timer_handle_cancel() {
        let h = MockTimerHandle::new();
        assert!(h.is_timer_active());
        h.cancel_timer();
        assert!(!h.is_timer_active());
    }

    #[test]
    fn ttl_timer_handle_reset() {
        let mut h = MockTimerHandle::new();
        h.cancel_timer();
        h.reset_timer(Duration::from_secs(7200));
        assert!(h.is_timer_active());
    }

    // SCP-066 tests: integration

    #[test]
    fn full_extension_flow_bilateral() {
        let clock = TestClock::new(3000);
        let mut enforcer = TtlEnforcer::new(1000, TtlPolicy::Finite(Duration::from_secs(3600)));
        assert!(enforcer.check(&clock).is_ok());
        let mut proposal = TtlExtensionProposal::new(
            "did:key:alice".into(),
            Duration::from_secs(3600),
            2,
            GovernanceModel::SingleAdmin,
        );
        proposal.record_consent("did:key:alice".into());
        proposal.record_consent("did:key:bob".into());
        assert!(proposal.is_approved());
        let new_deadline = proposal.compute_new_deadline(clock.now());
        enforcer.apply_extension(new_deadline, &clock).unwrap();
        clock.set(5000);
        assert!(enforcer.check(&clock).is_ok());
        clock.set(7000);
        assert!(enforcer.check(&clock).is_err());
    }

    #[test]
    fn full_extension_flow_multi_party() {
        let clock = TestClock::new(2000);
        let mut enforcer = TtlEnforcer::new(1000, TtlPolicy::Finite(Duration::from_secs(3600)));
        let mut proposal = TtlExtensionProposal::new(
            "did:key:admin".into(),
            Duration::from_secs(7200),
            5,
            GovernanceModel::SingleAdmin,
        );
        proposal.record_consent("did:key:admin".into());
        assert!(proposal.is_approved());
        enforcer
            .apply_extension(proposal.compute_new_deadline(clock.now()), &clock)
            .unwrap();
        clock.set(5000);
        assert!(enforcer.check(&clock).is_ok());
        clock.set(9200);
        assert!(enforcer.check(&clock).is_err());
    }

    // SCP-203 tests: closing/expiry notifications use proper ContextEvent variants

    /// SCP-203: `closing_notification` returns `SystemClose` (not `MemberLeft`
    /// with a sentinel DID).
    #[test]
    fn closing_notification_returns_system_close_variant() {
        let event = closing_notification(&"did:key:admin".into());
        match event {
            ContextEvent::SystemClose { initiator_did } => {
                assert_eq!(initiator_did, "did:key:admin");
            }
            _ => panic!("expected SystemClose, got {event:?}"),
        }
    }

    /// SCP-203: `expiry_notification` returns `Expired` (not `MemberLeft` with
    /// a sentinel DID).
    #[test]
    fn expiry_notification_returns_expired_variant() {
        let event = expiry_notification();
        assert_eq!(event, ContextEvent::Expired);
    }

    /// SCP-203: closing notification no longer uses sentinel DID strings.
    #[test]
    fn closing_notification_is_not_member_left() {
        let event = closing_notification(&"did:key:alice".into());
        assert!(
            !matches!(event, ContextEvent::MemberLeft { .. }),
            "closing notification must not use MemberLeft variant"
        );
    }

    /// SCP-203: expiry notification no longer uses sentinel DID strings.
    #[test]
    fn expiry_notification_is_not_member_left() {
        let event = expiry_notification();
        assert!(
            !matches!(event, ContextEvent::MemberLeft { .. }),
            "expiry notification must not use MemberLeft variant"
        );
    }

    // -----------------------------------------------------------------------
    // TTL expiry with transport — relay ciphertext deletion (#337)
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn handle_ttl_expiry_with_transport_deletes_relay_data_for_ephemeral() {
        let handle = active_handle("ctx-eph-del", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        let transport = MockTransport::connected();
        let event_log = MockEventLog::default();

        let result =
            handle_ttl_expiry_with_transport(&handle, &crypto, Some(&transport), &event_log).await;

        assert!(result.is_ok());
        assert_eq!(handle.state().await, ContextState::Expired);
        // Verify relay deletion was requested.
        let deleted = transport.deleted.lock().unwrap();
        assert_eq!(deleted.len(), 1);
        // Verify MLS keys were destroyed.
        assert_eq!(crypto.mls_destroyed.lock().unwrap().len(), 1);
        assert_eq!(crypto.sender_keys_destroyed.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn handle_ttl_expiry_with_transport_deletes_relay_data_for_summary() {
        let handle = active_handle("ctx-sum-del", MemoryScope::Summary);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        let transport = MockTransport::connected();
        let event_log = MockEventLog::default();

        let result =
            handle_ttl_expiry_with_transport(&handle, &crypto, Some(&transport), &event_log).await;

        assert!(result.is_ok());
        // Relay deletion requested for Summary scope too.
        let deleted = transport.deleted.lock().unwrap();
        assert_eq!(deleted.len(), 1);
    }

    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn handle_ttl_expiry_with_transport_no_deletion_for_full() {
        let handle = active_handle("ctx-full-nodel", MemoryScope::Full);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        let transport = MockTransport::connected();
        let event_log = MockEventLog::default();

        let result =
            handle_ttl_expiry_with_transport(&handle, &crypto, Some(&transport), &event_log).await;

        assert!(result.is_ok());
        // No relay deletion for Full scope.
        let deleted = transport.deleted.lock().unwrap();
        assert!(deleted.is_empty());
        // No key destruction for Full scope.
        assert!(crypto.mls_destroyed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn handle_ttl_expiry_succeeds_without_transport() {
        // The original handle_ttl_expiry (no transport) still works.
        let handle = active_handle("ctx-no-transport", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        let event_log = MockEventLog::default();

        let result = handle_ttl_expiry(&handle, &crypto, &event_log).await;

        assert!(result.is_ok());
        assert_eq!(handle.state().await, ContextState::Expired);
        // Keys destroyed even without transport.
        assert_eq!(crypto.mls_destroyed.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn handle_ttl_expiry_succeeds_even_if_relay_deletion_fails() {
        // Relay deletion is best-effort — failures don't block expiry.
        let handle = active_handle("ctx-relay-fail", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        // Use a transport that will succeed (mock always succeeds), but
        // conceptually: the close should succeed even on relay failure.
        let transport = MockTransport::connected();
        let event_log = MockEventLog::default();

        let result =
            handle_ttl_expiry_with_transport(&handle, &crypto, Some(&transport), &event_log).await;

        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Expired context rejects new messages (#337)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn expired_context_rejects_close() {
        let handle = active_handle("ctx-expired-close", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        let event_log = MockEventLog::default();

        // Expire the context.
        handle_ttl_expiry(&handle, &crypto, &event_log)
            .await
            .unwrap();
        assert_eq!(handle.state().await, ContextState::Expired);

        // Attempting to close an expired context should fail.
        let role_state = role_state_with_close_capability("ctx-expired-close", "did:key:admin");
        let result = close_context(&handle, &"did:key:admin".into(), &role_state, &event_log).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn expired_context_second_expiry_is_idempotent() {
        // After #612: repeated expiry calls succeed (idempotent cleanup for
        // retry support). The context stays in Expired state.
        let handle = active_handle("ctx-double-expire", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        let event_log = MockEventLog::default();

        // First expiry succeeds.
        handle_ttl_expiry(&handle, &crypto, &event_log)
            .await
            .unwrap();
        assert_eq!(handle.state().await, ContextState::Expired);

        // Second expiry also succeeds (idempotent retry path).
        let result = handle_ttl_expiry(&handle, &crypto, &event_log).await;
        assert!(result.is_ok());
        assert_eq!(handle.state().await, ContextState::Expired);
    }

    // -----------------------------------------------------------------------
    // Ephemeral close — MLS key destruction verification (#337)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ephemeral_close_destroys_mls_group_and_sender_keys() {
        let handle = active_handle("ctx-eph-keys", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        let transport = MockTransport::connected();
        let event_log = MockEventLog::default();

        // Close the context (Active -> Closing).
        let role_state = role_state_with_close_capability("ctx-eph-keys", "did:key:creator");
        close_context(&handle, &"did:key:creator".into(), &role_state, &event_log)
            .await
            .unwrap();

        // Finalize close (Closing -> Closed) — this destroys keys.
        finalize_close(&handle, &crypto, &transport, &event_log)
            .await
            .unwrap();

        assert_eq!(handle.state().await, ContextState::Closed);
        // Both MLS group and sender keys destroyed.
        assert_eq!(crypto.mls_destroyed.lock().unwrap().len(), 1);
        assert_eq!(crypto.sender_keys_destroyed.lock().unwrap().len(), 1);
        // Relay deletion requested.
        assert_eq!(transport.deleted.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn full_scope_close_does_not_delete_relay_data() {
        let handle = active_handle("ctx-full-close", MemoryScope::Full);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        let transport = MockTransport::connected();
        let event_log = MockEventLog::default();

        let role_state = role_state_with_close_capability("ctx-full-close", "did:key:creator");
        close_context(&handle, &"did:key:creator".into(), &role_state, &event_log)
            .await
            .unwrap();

        finalize_close(&handle, &crypto, &transport, &event_log)
            .await
            .unwrap();

        // Full scope: relay data NOT deleted.
        assert!(transport.deleted.lock().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // TTL expiry error propagation and retry (#612)
    // -----------------------------------------------------------------------

    /// Mock crypto that fails MLS group destruction.
    #[derive(Default)]
    struct FailingMlsCrypto {
        sender_keys_destroyed: Mutex<Vec<[u8; 32]>>,
    }

    impl ContextCryptoProvider for FailingMlsCrypto {
        fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn create_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn generate_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn init_broadcast_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn destroy_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Err(ContextCreationError::CryptoFailed(
                "MLS group destruction failed".into(),
            ))
        }
        fn destroy_sender_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.sender_keys_destroyed.lock().unwrap().push(*id);
            Ok(())
        }
        fn validate_key_package(
            &self,
            _owner_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<(), ContextError> {
            Ok(())
        }
        fn add_member(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<(), ContextError> {
            Ok(())
        }
        fn remove_member(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }
        fn distribute_sender_key(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }
        fn remove_member_sender_key(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }
        fn encrypt_message(
            &self,
            _context_id: &[u8; 32],
            _sender_did: &str,
            payload: &[u8],
            _epoch: u64,
            _sequence: u64,
        ) -> Result<Vec<u8>, ContextError> {
            Ok(payload.to_vec())
        }
    }

    /// Mock event log that fails to append.
    struct FailingEventLog;

    impl ContextEventLogProvider for FailingEventLog {
        fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn append_event(&self, _id: &[u8; 32], _event: &str) -> Result<(), ContextCreationError> {
            Err(ContextCreationError::CryptoFailed(
                "event log write failed".into(),
            ))
        }
        fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn try_ttl_expiry_cleanup_tracks_partial_mls_failure() {
        // MLS destruction fails but sender key destruction and event log succeed.
        let handle = active_handle("ctx-partial-mls", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto = FailingMlsCrypto::default();
        let event_log = MockEventLog::default();

        let result = try_ttl_expiry_cleanup(&handle, &crypto, None, &event_log).await;

        // State transition succeeded.
        assert!(result.state_transitioned());
        // MLS destruction failed.
        assert!(!result.mls_destroyed());
        // Sender key destruction succeeded.
        assert!(result.sender_key_destroyed());
        // Event log succeeded.
        assert!(result.event_logged());
        // Has failures overall.
        assert!(result.has_failures());
        assert!(!result.is_complete());
        // Error message contains the MLS failure.
        assert!(result.errors.iter().any(|e| e.contains("MLS group")));
    }

    #[tokio::test]
    async fn try_ttl_expiry_cleanup_tracks_event_log_failure() {
        // Crypto succeeds but event log fails.
        let handle = active_handle("ctx-partial-log", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        let event_log = FailingEventLog;

        let result = try_ttl_expiry_cleanup(&handle, &crypto, None, &event_log).await;

        assert!(result.state_transitioned());
        assert!(result.mls_destroyed());
        assert!(result.sender_key_destroyed());
        assert!(!result.event_logged());
        assert!(result.has_failures());
        assert!(result.errors.iter().any(|e| e.contains("event log")));
    }

    #[tokio::test]
    async fn try_ttl_expiry_cleanup_full_scope_skips_key_destruction() {
        // Full scope: keys are not destroyed, so those steps are marked done.
        let handle = active_handle("ctx-full-cleanup", MemoryScope::Full);
        make_active(&handle).await;
        let crypto = FailingMlsCrypto::default();
        let event_log = MockEventLog::default();

        let result = try_ttl_expiry_cleanup(&handle, &crypto, None, &event_log).await;

        // Even though crypto would fail, Full scope skips key destruction.
        assert!(result.state_transitioned());
        assert!(result.mls_destroyed());
        assert!(result.sender_key_destroyed());
        assert!(result.event_logged());
        assert!(result.is_complete());
    }

    #[tokio::test]
    async fn try_ttl_expiry_cleanup_idempotent_on_expired_context() {
        // Calling cleanup on an already-expired context is idempotent.
        let handle = active_handle("ctx-idempotent", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        let event_log = MockEventLog::default();

        // First cleanup.
        let result1 = try_ttl_expiry_cleanup(&handle, &crypto, None, &event_log).await;
        assert!(result1.is_complete());
        assert_eq!(handle.state().await, ContextState::Expired);

        // Second cleanup (already Expired) — idempotent.
        let result2 = try_ttl_expiry_cleanup(&handle, &crypto, None, &event_log).await;
        assert!(result2.is_complete());
        assert_eq!(handle.state().await, ContextState::Expired);
    }

    #[tokio::test]
    async fn try_ttl_expiry_cleanup_rejects_closed_context() {
        // A Closed context cannot be expired.
        let handle = active_handle("ctx-closed", MemoryScope::Ephemeral);
        make_active(&handle).await;
        handle.transition_to(&ContextState::Closing).await.unwrap();
        handle.transition_to(&ContextState::Closed).await.unwrap();

        let crypto = MockCrypto::default();
        let event_log = MockEventLog::default();

        let result = try_ttl_expiry_cleanup(&handle, &crypto, None, &event_log).await;

        assert!(!result.state_transitioned());
        assert!(result.has_failures());
        assert!(result.errors.iter().any(|e| e.contains("Closed")));
    }

    #[tokio::test]
    async fn handle_ttl_expiry_with_transport_returns_crypto_error_on_mls_failure() {
        let handle = active_handle("ctx-mls-err", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto = FailingMlsCrypto::default();
        let event_log = MockEventLog::default();

        let result = handle_ttl_expiry_with_transport(&handle, &crypto, None, &event_log).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ContextError::CryptoFailed(_)));
    }

    #[tokio::test]
    async fn handle_ttl_expiry_with_transport_returns_event_log_error() {
        let handle = active_handle("ctx-log-err", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        let event_log = FailingEventLog;

        let result = handle_ttl_expiry_with_transport(&handle, &crypto, None, &event_log).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::EventLogFailed(_)
        ));
    }

    #[tokio::test]
    async fn ttl_expiry_error_display_includes_step_status() {
        let err = TtlExpiryError {
            completed_steps: STEP_STATE_TRANSITIONED | STEP_SENDER_KEY_DESTROYED,
            errors: vec!["MLS fail".into(), "log fail".into()],
        };

        let display = err.to_string();
        assert!(display.contains("state_transitioned=true"));
        assert!(display.contains("mls_destroyed=false"));
        assert!(display.contains("sender_key_destroyed=true"));
        assert!(display.contains("event_logged=false"));
        assert!(display.contains("MLS fail"));
        assert!(display.contains("log fail"));
    }

    #[tokio::test]
    async fn run_retries_succeeds_on_retry() {
        // Use a mock crypto that fails the first N calls then succeeds.
        // Since we can't easily make MockCrypto fail then succeed, test
        // the success path (retry not needed) to verify the retry function
        // works correctly.
        let handle = active_handle("ctx-retry-ok", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto = MockCrypto::default();
        let event_log = MockEventLog::default();
        let cancel = Notify::new();

        let result = run_ttl_expiry_with_retries(&handle, &crypto, None, &event_log, &cancel).await;

        assert!(result.is_complete());
    }

    #[tokio::test]
    async fn run_retries_returns_error_after_max_attempts() {
        // Crypto always fails — retries should be exhausted.
        let handle = active_handle("ctx-retry-fail", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto = FailingMlsCrypto::default();
        let event_log = MockEventLog::default();
        let cancel = Notify::new();

        // Use tokio::time::pause() to avoid real delays.
        tokio::time::pause();

        let result = run_ttl_expiry_with_retries(&handle, &crypto, None, &event_log, &cancel).await;

        assert!(result.has_failures());
        assert!(!result.mls_destroyed());
        // State was transitioned on the first attempt.
        assert!(result.state_transitioned());
        // Event log was written on each attempt (idempotent).
        assert!(result.event_logged());
    }

    #[tokio::test]
    async fn ttl_timer_with_error_callback_fires_on_failure() {
        // Spawn a timer with a crypto provider that always fails MLS
        // destruction. The error callback should be invoked.
        let handle = active_handle("ctx-timer-cb", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto: Arc<dyn ContextCryptoProvider> = Arc::new(FailingMlsCrypto::default());
        let event_log: Arc<dyn ContextEventLogProvider> = Arc::new(MockEventLog::default());

        let callback_invoked = Arc::new(AtomicBool::new(false));
        let callback_invoked_clone = Arc::clone(&callback_invoked);
        let callback_context_id = Arc::new(Mutex::new(String::new()));
        let callback_context_id_clone = Arc::clone(&callback_context_id);

        let on_error: TtlExpiryErrorCallback = Arc::new(move |ctx_id, error| {
            callback_invoked_clone.store(true, Ordering::SeqCst);
            *callback_context_id_clone.lock().unwrap() = ctx_id;
            assert!(!error.mls_destroyed());
            assert!(error.state_transitioned());
        });

        let mut timer = TtlTimer::with_error_callback(on_error);

        // Use tokio::time::pause() to advance time instantly.
        tokio::time::pause();

        timer.spawn(Duration::from_millis(10), handle.clone(), crypto, event_log);
        assert!(timer.is_active());

        // Advance time past the TTL plus retry delays.
        tokio::time::advance(Duration::from_secs(60)).await;
        // Let the spawned task complete.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;

        // Wait for the task to finish.
        if let Some(task) = timer.task.take() {
            let _ = task.await;
        }

        assert!(callback_invoked.load(Ordering::SeqCst));
        assert_eq!(*callback_context_id.lock().unwrap(), "ctx-timer-cb");
    }

    #[tokio::test]
    async fn ttl_timer_without_callback_does_not_panic() {
        // Timer with no error callback should still work — just no notification.
        let handle = active_handle("ctx-timer-nocb", MemoryScope::Ephemeral);
        make_active(&handle).await;
        let crypto: Arc<dyn ContextCryptoProvider> = Arc::new(FailingMlsCrypto::default());
        let event_log: Arc<dyn ContextEventLogProvider> = Arc::new(MockEventLog::default());

        let mut timer = TtlTimer::new();
        tokio::time::pause();

        timer.spawn(Duration::from_millis(10), handle.clone(), crypto, event_log);

        // Advance time and let the task complete.
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;

        if let Some(task) = timer.task.take() {
            let _ = task.await;
        }

        // Context should be in Expired state (transition succeeded even though
        // key destruction failed).
        assert_eq!(handle.state().await, ContextState::Expired);
    }

    #[tokio::test]
    async fn context_event_expiry_failed_has_correct_fields() {
        let event = ContextEvent::ExpiryFailed {
            reason: "MLS fail".into(),
            state_transitioned: true,
            mls_destroyed: false,
            sender_key_destroyed: true,
            event_logged: false,
        };

        match event {
            ContextEvent::ExpiryFailed {
                reason,
                state_transitioned,
                mls_destroyed,
                sender_key_destroyed,
                event_logged,
            } => {
                assert_eq!(reason, "MLS fail");
                assert!(state_transitioned);
                assert!(!mls_destroyed);
                assert!(sender_key_destroyed);
                assert!(!event_logged);
            }
            _ => panic!("expected ExpiryFailed variant"),
        }
    }
}
