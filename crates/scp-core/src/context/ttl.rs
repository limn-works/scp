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
            ExtensionConsentMode::Governance => match governance {
                GovernanceModel::SingleAdmin => 1,
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

    crypto
        .destroy_mls_group(&context_id_bytes)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
    crypto
        .destroy_sender_key(&context_id_bytes)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    if memory_scope == MemoryScope::Ephemeral || memory_scope == MemoryScope::Summary {
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
/// See ADR-008 acceptance criterion 7.
///
/// # Errors
///
/// Returns [`ContextError::ContextNotActive`] if the context is not `Active`.
pub async fn handle_ttl_expiry(
    handle: &ContextHandle,
    crypto: &dyn ContextCryptoProvider,
    event_log: &dyn ContextEventLogProvider,
) -> Result<(), ContextError> {
    let state = handle.state().await;
    if state != ContextState::Active {
        return Err(ContextError::ContextNotActive);
    }

    let context_id = handle.context_id().to_owned();
    let context_id_bytes = context_id_to_bytes(&context_id);
    let memory_scope = handle.params().memory_scope;

    handle.transition_to(&ContextState::Expired).await?;

    if memory_scope == MemoryScope::Ephemeral || memory_scope == MemoryScope::Summary {
        let _ = crypto.destroy_mls_group(&context_id_bytes);
        let _ = crypto.destroy_sender_key(&context_id_bytes);
    }

    event_log.append_context_event(&context_id_bytes, "ContextExpired")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// TtlTimer -- tokio-based TTL timer management
// ---------------------------------------------------------------------------

/// Manages a TTL timer for a single context.
///
/// See ADR-008 acceptance criterion 9.
pub struct TtlTimer {
    /// The spawned timer task handle. `None` if no TTL is configured.
    pub(crate) task: Option<JoinHandle<()>>,
    /// Cancellation signal.
    pub(crate) cancel: Arc<Notify>,
}

impl TtlTimer {
    /// Creates a new `TtlTimer` without starting any task.
    #[must_use]
    pub fn new() -> Self {
        Self {
            task: None,
            cancel: Arc::new(Notify::new()),
        }
    }

    /// Spawns a TTL timer task that fires after the given duration.
    pub fn spawn(
        &mut self,
        duration: Duration,
        handle: ContextHandle,
        crypto: Arc<dyn ContextCryptoProvider>,
        event_log: Arc<dyn ContextEventLogProvider>,
    ) {
        let cancel = self.cancel.clone();

        let task = tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(duration) => {
                    let _ = handle_ttl_expiry(&handle, crypto.as_ref(), event_log.as_ref()).await;
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
    clippy::iter_on_single_items
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
        fn validate_key_package(&self, _owner_did: &str) -> Result<(), ContextError> {
            Ok(())
        }
        fn add_member(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
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
}
