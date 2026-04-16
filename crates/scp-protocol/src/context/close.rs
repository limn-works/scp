//! Context close orchestration per `ContextCloseReason`.
//!
//! Implements ADR-018 (`.docs/adrs/phase-4.md`), acceptance criteria 5 and 6:
//!
//! - [`ContextCloseReason`] -- Why a context is closing (TTL expired,
//!   governance decision, all members left).
//! - [`CloseOrchestrator`] -- Dispatches close to the correct destruction path
//!   based on [`MemoryScope`].
//! - [`SummaryVerificationWindow`] -- Tracks a configurable verification period
//!   during which participants verify a summary against the event log.
//! - [`CloseEvent`] -- Structured event recorded in the context event log when
//!   a close is initiated, a summary is verified, or keys are destroyed.
//!
//! # Close Sequencing
//!
//! Close orchestration coordinates three close triggers:
//! - **TTL expiry:** Automatic close when the context's TTL elapses.
//! - **Governance close:** Admin-initiated close via the `ContextClose` capability.
//! - **All members left:** The last member departure triggers context close.
//!
//! # Memory Scope Dispatch
//!
//! - **Ephemeral:** Keys destroyed immediately via [`KeyDestructionOrchestrator`].
//! - **Summary:** Verification window opens; participants verify summary; after
//!   the window closes, keys are destroyed as ephemeral.
//! - **Full:** All keys and data are preserved. No destruction occurs.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::memory_scope::{
    BlobId, ContextId, KeyDestructionLevel, KeyDestructionOrchestrator, KeyDestructionResult,
};
use super::{ContextError, MemoryScope};
use scp_primitives::DID;

// ---------------------------------------------------------------------------
// IncompleteVerificationPolicy
// ---------------------------------------------------------------------------

/// Policy controlling what happens when the summary verification window TTL
/// expires before all members have verified.
///
/// Set at context creation in [`super::params::ContextParams`] and consumed by the close
/// orchestrator. Defaults to [`Proceed`](IncompleteVerificationPolicy::Proceed)
/// if not specified.
///
/// See spec §5.11 and issue #365.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum IncompleteVerificationPolicy {
    /// Proceed with close even if not all members verified.
    #[default]
    Proceed,
    /// Extend the verification window by the specified number of seconds.
    ExtendWindow {
        /// Number of seconds to extend the deadline by.
        duration_secs: u64,
    },
}

// ---------------------------------------------------------------------------
// DisputeAction
// ---------------------------------------------------------------------------

/// Action taken by an admin or governance vote to resolve a disputed summary.
///
/// See issue #365.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisputeAction {
    /// Accept the current summary and proceed with close.
    Proceed,
    /// Replace the summary with a revised version and re-open verification.
    Revise {
        /// The replacement summary (JSON value).
        new_summary: String,
    },
}

// ---------------------------------------------------------------------------
// VerificationState
// ---------------------------------------------------------------------------

/// Internal state of the summary verification window.
///
/// Tracks whether verification is proceeding normally or has been disputed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationState {
    /// Normal verification in progress.
    Verifying,
    /// A member has disputed the summary. Awaiting resolution.
    Disputed {
        /// DID of the member who rejected the summary.
        rejector_did: DID,
        /// Reason for the rejection.
        reason: String,
    },
    /// Dispute resolved (either proceeded or revised).
    Resolved {
        /// The action taken to resolve the dispute.
        action: DisputeAction,
    },
}

// ---------------------------------------------------------------------------
// ContextCloseReason
// ---------------------------------------------------------------------------

/// The reason a context is being closed.
///
/// Defines the three close triggers from ADR-018. The close reason is recorded
/// in the [`CloseEvent`] for audit and provenance purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextCloseReason {
    /// The context's TTL has elapsed. Automatic close -- no governance
    /// override is possible.
    TtlExpired,
    /// An admin or governance decision closed the context. The initiator must
    /// hold the `ContextClose` capability.
    GovernanceClosed,
    /// All members have left the context. The last departure triggers close.
    AllMembersLeft,
}

impl std::fmt::Display for ContextCloseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TtlExpired => write!(f, "TtlExpired"),
            Self::GovernanceClosed => write!(f, "GovernanceClosed"),
            Self::AllMembersLeft => write!(f, "AllMembersLeft"),
        }
    }
}

// ---------------------------------------------------------------------------
// Default verification window duration
// ---------------------------------------------------------------------------

/// Default summary verification window duration in seconds.
///
/// Contexts may override this via their own configuration. This constant
/// provides the protocol-level default when no explicit duration is set.
pub const DEFAULT_VERIFICATION_WINDOW_SECS: u64 = 300;

// ---------------------------------------------------------------------------
// SummaryVerificationWindow
// ---------------------------------------------------------------------------

/// Tracks the verification period for a summary close.
///
/// During the verification window, participants verify the generated summary
/// against the event log. Each participant who verifies records their DID. Once
/// the window closes (determined by comparing `deadline` against the current
/// time), keys can be destroyed as in an ephemeral close.
///
/// See ADR-018 acceptance criterion 6.
#[derive(Debug, Clone)]
pub struct SummaryVerificationWindow {
    /// Context identifier.
    context_id: ContextId,
    /// Unix timestamp (seconds) when the verification window opened.
    opened_at: u64,
    /// Unix timestamp (seconds) when the verification window closes.
    deadline: u64,
    /// DIDs of participants who have verified the summary.
    verified_by: HashSet<String>,
    /// Total member count at the time the window was opened.
    member_count: usize,
    /// Current state of the verification window.
    state: VerificationState,
    /// Policy for handling incomplete verification at TTL expiry.
    incomplete_policy: IncompleteVerificationPolicy,
}

impl SummaryVerificationWindow {
    /// Creates a new verification window.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The context being closed.
    /// * `opened_at` -- Unix timestamp (seconds) when the window opens.
    /// * `duration_secs` -- Duration of the verification window in seconds.
    /// * `member_count` -- Total member count at window open time.
    #[must_use]
    pub fn new(
        context_id: ContextId,
        opened_at: u64,
        duration_secs: u64,
        member_count: usize,
    ) -> Self {
        Self::with_policy(
            context_id,
            opened_at,
            duration_secs,
            member_count,
            IncompleteVerificationPolicy::default(),
        )
    }

    /// Creates a new verification window with a specific incomplete
    /// verification policy.
    #[must_use]
    pub fn with_policy(
        context_id: ContextId,
        opened_at: u64,
        duration_secs: u64,
        member_count: usize,
        incomplete_policy: IncompleteVerificationPolicy,
    ) -> Self {
        Self {
            context_id,
            opened_at,
            deadline: opened_at.saturating_add(duration_secs),
            verified_by: HashSet::new(),
            member_count,
            state: VerificationState::Verifying,
            incomplete_policy,
        }
    }

    /// Records a participant's verification of the summary.
    ///
    /// Returns `true` if this is a new verification (the DID had not
    /// previously verified). Returns `false` if the participant already
    /// verified.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextClosed`] if the verification window
    /// has already closed (based on the provided `now` timestamp).
    pub fn verify_summary(
        &mut self,
        participant_did: &str,
        now: u64,
    ) -> Result<bool, ContextError> {
        if now >= self.deadline {
            return Err(ContextError::ContextClosed);
        }
        if self.state != VerificationState::Verifying {
            return Err(ContextError::InvalidState(format!(
                "cannot verify summary: window is in {:?} state, expected Verifying",
                self.state
            )));
        }
        Ok(self.verified_by.insert(participant_did.to_owned()))
    }

    /// Returns `true` if the verification window has closed.
    #[must_use]
    pub const fn is_window_closed(&self, now: u64) -> bool {
        now >= self.deadline
    }

    /// Returns the context identifier.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the Unix timestamp when the window was opened.
    #[must_use]
    pub const fn opened_at(&self) -> u64 {
        self.opened_at
    }

    /// Returns the Unix timestamp when the window closes.
    #[must_use]
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Returns the number of participants who have verified the summary.
    #[must_use]
    pub fn verification_count(&self) -> usize {
        self.verified_by.len()
    }

    /// Returns the total member count at window open time.
    #[must_use]
    pub const fn member_count(&self) -> usize {
        self.member_count
    }

    /// Returns the set of DIDs that have verified the summary.
    #[must_use]
    pub const fn verified_participants(&self) -> &HashSet<String> {
        &self.verified_by
    }

    /// Returns the current verification state.
    #[must_use]
    pub const fn state(&self) -> &VerificationState {
        &self.state
    }

    /// Returns the incomplete verification policy.
    #[must_use]
    pub const fn incomplete_policy(&self) -> IncompleteVerificationPolicy {
        self.incomplete_policy
    }

    /// Rejects the summary, transitioning the window to the `Disputed` state.
    ///
    /// A member calls this when they believe the summary does not accurately
    /// reflect the context's event log.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextClosed`] if the verification window
    /// has already closed.
    /// Returns [`ContextError::InvalidState`] if the window is not in the
    /// `Verifying` state (already disputed or resolved).
    pub fn reject(
        &mut self,
        member_did: &DID,
        reason: String,
        now: u64,
    ) -> Result<(), ContextError> {
        if now >= self.deadline {
            return Err(ContextError::ContextClosed);
        }
        if self.state != VerificationState::Verifying {
            return Err(ContextError::InvalidState(format!(
                "cannot reject summary: window is in {:?} state, expected Verifying",
                self.state
            )));
        }
        self.state = VerificationState::Disputed {
            rejector_did: member_did.clone(),
            reason,
        };
        Ok(())
    }

    /// Resolves a dispute, either proceeding with the current summary or
    /// replacing it with a revised version.
    ///
    /// For `DisputeAction::Revise`, the window resets: `verified_by` is cleared,
    /// the deadline is extended by the original window duration, and the state
    /// returns to `Verifying` so members can verify the new summary.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidState`] if the window is not in the
    /// `Disputed` state.
    pub fn resolve_dispute(&mut self, action: DisputeAction, now: u64) -> Result<(), ContextError> {
        if !matches!(self.state, VerificationState::Disputed { .. }) {
            return Err(ContextError::InvalidState(format!(
                "cannot resolve dispute: window is in {:?} state, expected Disputed",
                self.state
            )));
        }
        match action {
            action @ DisputeAction::Proceed => {
                self.state = VerificationState::Resolved { action };
            }
            DisputeAction::Revise { .. } => {
                // Re-open verification: clear votes, extend deadline, return to Verifying.
                self.verified_by.clear();
                let original_duration = self.deadline.saturating_sub(self.opened_at);
                self.deadline = now.saturating_add(original_duration);
                self.opened_at = now;
                self.state = VerificationState::Verifying;
            }
        }
        Ok(())
    }

    /// Handles TTL expiry according to the incomplete verification policy.
    ///
    /// Returns `true` if the window should proceed to close (policy is
    /// `Proceed`). Returns `false` if the window was extended (policy is
    /// `ExtendWindow`).
    pub const fn handle_ttl_expiry(&mut self, now: u64) -> bool {
        if !self.is_window_closed(now) {
            return false;
        }
        match self.incomplete_policy {
            IncompleteVerificationPolicy::Proceed => true,
            IncompleteVerificationPolicy::ExtendWindow { duration_secs } => {
                self.deadline = now.saturating_add(duration_secs);
                false
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CloseEvent
// ---------------------------------------------------------------------------

/// Structured event recorded in the context event log during close
/// orchestration.
///
/// Each variant captures the close-related metadata needed for audit trails,
/// provenance tracking, and close sequencing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloseEvent {
    /// Close has been initiated for the given reason.
    CloseInitiated {
        /// The reason the context is closing.
        reason: ContextCloseReason,
        /// The memory scope that determines the destruction path.
        memory_scope: MemoryScope,
        /// Unix timestamp (seconds) when the close was initiated.
        initiated_at: u64,
    },
    /// A summary verification window has been opened (Summary scope only).
    SummaryWindowOpened {
        /// Unix timestamp when the window opened.
        opened_at: u64,
        /// Unix timestamp when the window will close.
        deadline: u64,
        /// Number of members expected to verify.
        member_count: usize,
    },
    /// A participant verified the summary during the verification window.
    SummaryVerified {
        /// The DID of the verifying participant.
        participant_did: String,
        /// Unix timestamp when the verification was recorded.
        verified_at: u64,
    },
    /// A participant rejected the summary during the verification window.
    SummaryRejected {
        /// The DID of the rejecting participant.
        rejector_did: String,
        /// The rejection reason.
        reason: String,
        /// Unix timestamp when the rejection was recorded.
        rejected_at: u64,
    },
    /// A summary dispute was resolved.
    SummaryDisputeResolved {
        /// The action taken to resolve the dispute.
        action: DisputeAction,
        /// Unix timestamp when the dispute was resolved.
        resolved_at: u64,
    },
    /// Keys have been destroyed (Ephemeral or Summary post-window).
    KeysDestroyed {
        /// The attestation level achieved during key destruction.
        attestation_level: KeyDestructionLevel,
        /// Unix timestamp when keys were destroyed.
        destroyed_at: u64,
    },
    /// Close completed with full data preservation (Full scope).
    FullCloseCompleted {
        /// Unix timestamp when the full close completed.
        completed_at: u64,
    },
}

// ---------------------------------------------------------------------------
// CloseRequest
// ---------------------------------------------------------------------------

/// Parameters for initiating a context close via [`CloseOrchestrator`].
///
/// Groups the arguments for [`CloseOrchestrator::initiate_close`] into a
/// single struct to keep the public API ergonomic.
pub struct CloseRequest<'r> {
    /// The context being closed.
    pub context_id: &'r str,
    /// Why the context is closing.
    pub reason: ContextCloseReason,
    /// The context's memory scope (determines the destruction path).
    pub memory_scope: MemoryScope,
    /// Relay URLs where encrypted event data is stored.
    pub relay_urls: &'r [String],
    /// Blob identifiers of encrypted event data to request deletion for.
    pub blob_ids: &'r [BlobId],
    /// Platform-provided key destruction attestation level.
    pub attestation_level: KeyDestructionLevel,
    /// Current member count (used for summary verification window).
    pub member_count: usize,
    /// Duration of the summary verification window in seconds. `None` uses
    /// [`DEFAULT_VERIFICATION_WINDOW_SECS`].
    pub verification_window_secs: Option<u64>,
    /// Current Unix timestamp (seconds).
    pub now: u64,
}

// ---------------------------------------------------------------------------
// CloseOrchestrator
// ---------------------------------------------------------------------------

/// Dispatches context close to the correct destruction path based on
/// [`MemoryScope`].
///
/// The orchestrator coordinates the close sequencing:
/// - **Ephemeral:** Immediate key destruction via [`KeyDestructionOrchestrator`].
/// - **Summary:** Opens a [`SummaryVerificationWindow`], then destroys keys
///   after the window closes.
/// - **Full:** Preserves all keys and data; no destruction occurs.
///
/// The orchestrator does not own the context state machine transitions --
/// those are handled by the caller (e.g., `close_context` and
/// `finalize_close` in `ttl.rs`). This module provides the destruction
/// logic only.
pub struct CloseOrchestrator<'a> {
    /// Key destruction orchestrator for Ephemeral and Summary scopes.
    key_destruction: KeyDestructionOrchestrator<'a>,
}

impl<'a> CloseOrchestrator<'a> {
    /// Creates a new close orchestrator with the given crypto provider.
    #[must_use]
    pub fn new(crypto: &'a dyn super::builder::ContextCryptoProvider) -> Self {
        Self {
            key_destruction: KeyDestructionOrchestrator::new(crypto),
        }
    }

    /// Initiates the close sequence based on the context's memory scope and
    /// close reason.
    ///
    /// Returns a [`CloseAction`] that describes what the caller should do
    /// next:
    /// - [`CloseAction::KeysDestroyed`] for Ephemeral scope (immediate).
    /// - [`CloseAction::VerificationWindowOpened`] for Summary scope.
    /// - [`CloseAction::Preserved`] for Full scope (no destruction).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if key destruction fails
    /// (Ephemeral scope only).
    #[allow(clippy::too_many_arguments)]
    pub async fn initiate_close(
        &self,
        context_id: &str,
        reason: ContextCloseReason,
        memory_scope: MemoryScope,
        relay_urls: &[String],
        blob_ids: &[BlobId],
        attestation_level: KeyDestructionLevel,
        member_count: usize,
        verification_window_secs: Option<u64>,
        now: u64,
    ) -> Result<CloseAction, ContextError> {
        match memory_scope {
            MemoryScope::Ephemeral => {
                let result = self
                    .key_destruction
                    .destroy_ephemeral_keys(
                        context_id,
                        relay_urls,
                        blob_ids,
                        attestation_level,
                        now,
                    )
                    .await?;

                Ok(CloseAction::KeysDestroyed {
                    reason,
                    result,
                    event: CloseEvent::KeysDestroyed {
                        attestation_level,
                        destroyed_at: now,
                    },
                })
            }

            MemoryScope::Summary => {
                let window_duration =
                    verification_window_secs.unwrap_or(DEFAULT_VERIFICATION_WINDOW_SECS);
                let window = SummaryVerificationWindow::new(
                    context_id.to_owned(),
                    now,
                    window_duration,
                    member_count,
                );

                let event = CloseEvent::SummaryWindowOpened {
                    opened_at: now,
                    deadline: now.saturating_add(window_duration),
                    member_count,
                };

                Ok(CloseAction::VerificationWindowOpened {
                    reason,
                    window,
                    event,
                })
            }

            MemoryScope::Full => Ok(CloseAction::Preserved {
                reason,
                event: CloseEvent::FullCloseCompleted { completed_at: now },
            }),
        }
    }

    /// Completes a summary close after the verification window has closed.
    ///
    /// Destroys keys using the same path as ephemeral close. This should be
    /// called only after [`SummaryVerificationWindow::is_window_closed`]
    /// returns `true`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if key destruction fails.
    /// Returns [`ContextError::ContextNotActive`] if the verification
    /// window has not yet closed.
    pub async fn complete_summary_close(
        &self,
        window: &SummaryVerificationWindow,
        relay_urls: &[String],
        blob_ids: &[BlobId],
        attestation_level: KeyDestructionLevel,
        now: u64,
    ) -> Result<KeyDestructionResult, ContextError> {
        if !window.is_window_closed(now) {
            return Err(ContextError::ContextNotActive);
        }

        self.key_destruction
            .destroy_ephemeral_keys(
                window.context_id(),
                relay_urls,
                blob_ids,
                attestation_level,
                now,
            )
            .await
    }
}

// ---------------------------------------------------------------------------
// CloseAction
// ---------------------------------------------------------------------------

/// The result of [`CloseOrchestrator::initiate_close`], describing the next
/// step for the caller.
#[derive(Debug)]
pub enum CloseAction {
    /// Keys were destroyed immediately (Ephemeral scope). The caller should
    /// transition the context to `Closed` and record the event.
    KeysDestroyed {
        /// The close reason.
        reason: ContextCloseReason,
        /// The key destruction result (attestation + relay deletion requests).
        result: KeyDestructionResult,
        /// The close event to record in the event log.
        event: CloseEvent,
    },
    /// A summary verification window was opened (Summary scope). The caller
    /// should allow participants to verify the summary during the window,
    /// then call [`CloseOrchestrator::complete_summary_close`] after the
    /// window closes.
    VerificationWindowOpened {
        /// The close reason.
        reason: ContextCloseReason,
        /// The verification window tracker.
        window: SummaryVerificationWindow,
        /// The event to record in the event log.
        event: CloseEvent,
    },
    /// All data was preserved (Full scope). The caller should transition the
    /// context to `Closed` and record the event.
    Preserved {
        /// The close reason.
        reason: ContextCloseReason,
        /// The close event to record in the event log.
        event: CloseEvent,
    },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::manual_let_else
)]
mod tests {
    use super::*;
    use crate::context::ContextError;
    use crate::context::builder::{ContextCreationError, ContextCryptoProvider};
    use std::sync::atomic::{AtomicBool, Ordering};

    // -----------------------------------------------------------------------
    // Mock crypto provider
    // -----------------------------------------------------------------------

    struct MockCryptoProvider {
        mls_destroyed: AtomicBool,
        sender_key_destroyed: AtomicBool,
        fail_mls: bool,
        fail_sender: bool,
    }

    impl MockCryptoProvider {
        fn new() -> Self {
            Self {
                mls_destroyed: AtomicBool::new(false),
                sender_key_destroyed: AtomicBool::new(false),
                fail_mls: false,
                fail_sender: false,
            }
        }

        fn failing_mls() -> Self {
            Self {
                mls_destroyed: AtomicBool::new(false),
                sender_key_destroyed: AtomicBool::new(false),
                fail_mls: true,
                fail_sender: false,
            }
        }
    }

    #[async_trait::async_trait]
    impl ContextCryptoProvider for MockCryptoProvider {
        async fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
            Ok(())
        }

        async fn create_mls_group(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }

        async fn generate_sender_key(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }

        async fn init_broadcast_key(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }

        async fn destroy_mls_group(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<(), ContextCreationError> {
            if self.fail_mls {
                return Err(ContextCreationError::CryptoFailed(
                    "MLS destruction failed".to_owned(),
                ));
            }
            self.mls_destroyed.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn destroy_sender_key(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<(), ContextCreationError> {
            if self.fail_sender {
                return Err(ContextCreationError::CryptoFailed(
                    "sender key destruction failed".to_owned(),
                ));
            }
            self.sender_key_destroyed.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn validate_key_package(
            &self,
            _owner_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        async fn add_member(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<crate::context::builder::AddMemberOutput, ContextError> {
            Ok(crate::context::builder::AddMemberOutput::default())
        }

        async fn remove_member(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<crate::context::builder::RemoveMemberOutput, ContextError> {
            Ok(crate::context::builder::RemoveMemberOutput::default())
        }

        async fn distribute_sender_key(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        async fn remove_member_sender_key(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // ContextCloseReason tests
    // -----------------------------------------------------------------------

    #[test]
    fn close_reason_display() {
        assert_eq!(format!("{}", ContextCloseReason::TtlExpired), "TtlExpired");
        assert_eq!(
            format!("{}", ContextCloseReason::GovernanceClosed),
            "GovernanceClosed"
        );
        assert_eq!(
            format!("{}", ContextCloseReason::AllMembersLeft),
            "AllMembersLeft"
        );
    }

    #[test]
    fn close_reason_variants_are_distinct() {
        assert_ne!(
            ContextCloseReason::TtlExpired,
            ContextCloseReason::GovernanceClosed
        );
        assert_ne!(
            ContextCloseReason::GovernanceClosed,
            ContextCloseReason::AllMembersLeft
        );
        assert_ne!(
            ContextCloseReason::TtlExpired,
            ContextCloseReason::AllMembersLeft
        );
    }

    #[test]
    fn close_reason_serialization_roundtrip() {
        let reasons = [
            ContextCloseReason::TtlExpired,
            ContextCloseReason::GovernanceClosed,
            ContextCloseReason::AllMembersLeft,
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).unwrap();
            let deserialized: ContextCloseReason = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, reason);
        }
    }

    // -----------------------------------------------------------------------
    // SummaryVerificationWindow tests
    // -----------------------------------------------------------------------

    #[test]
    fn verification_window_creation() {
        let window = SummaryVerificationWindow::new("ctx-1".to_owned(), 1000, 300, 3);
        assert_eq!(window.context_id(), "ctx-1");
        assert_eq!(window.opened_at(), 1000);
        assert_eq!(window.deadline(), 1300);
        assert_eq!(window.member_count(), 3);
        assert_eq!(window.verification_count(), 0);
    }

    #[test]
    fn verification_window_verify_summary_succeeds_during_window() {
        let mut window = SummaryVerificationWindow::new("ctx-1".to_owned(), 1000, 300, 3);
        let result = window.verify_summary("did:scp:alice", 1100);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(window.verification_count(), 1);
        assert!(window.verified_participants().contains("did:scp:alice"));
    }

    #[test]
    fn verification_window_duplicate_verification_returns_false() {
        let mut window = SummaryVerificationWindow::new("ctx-1".to_owned(), 1000, 300, 3);
        window.verify_summary("did:scp:alice", 1100).unwrap();
        let result = window.verify_summary("did:scp:alice", 1150);
        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert_eq!(window.verification_count(), 1);
    }

    #[test]
    fn verification_window_multiple_participants() {
        let mut window = SummaryVerificationWindow::new("ctx-1".to_owned(), 1000, 300, 3);
        window.verify_summary("did:scp:alice", 1100).unwrap();
        window.verify_summary("did:scp:bob", 1150).unwrap();
        window.verify_summary("did:scp:carol", 1200).unwrap();
        assert_eq!(window.verification_count(), 3);
    }

    #[test]
    fn verification_window_rejects_after_deadline() {
        let mut window = SummaryVerificationWindow::new("ctx-1".to_owned(), 1000, 300, 3);
        let result = window.verify_summary("did:scp:alice", 1300);
        assert!(result.is_err());
        match result {
            Err(ContextError::ContextClosed) => {}
            _ => panic!("expected ContextClosed error"),
        }
    }

    #[test]
    fn verification_window_is_window_closed() {
        let window = SummaryVerificationWindow::new("ctx-1".to_owned(), 1000, 300, 3);
        assert!(!window.is_window_closed(1000));
        assert!(!window.is_window_closed(1299));
        assert!(window.is_window_closed(1300));
        assert!(window.is_window_closed(2000));
    }

    #[test]
    fn verification_window_saturating_deadline() {
        let window = SummaryVerificationWindow::new("ctx-1".to_owned(), u64::MAX - 10, 300, 1);
        assert_eq!(window.deadline(), u64::MAX);
    }

    // -----------------------------------------------------------------------
    // CloseEvent tests
    // -----------------------------------------------------------------------

    #[test]
    fn close_event_close_initiated_serialization_roundtrip() {
        let event = CloseEvent::CloseInitiated {
            reason: ContextCloseReason::TtlExpired,
            memory_scope: MemoryScope::Ephemeral,
            initiated_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: CloseEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, event);
    }

    #[test]
    fn close_event_summary_window_opened_serialization_roundtrip() {
        let event = CloseEvent::SummaryWindowOpened {
            opened_at: 1_700_000_000,
            deadline: 1_700_000_300,
            member_count: 3,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: CloseEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, event);
    }

    #[test]
    fn close_event_summary_verified_serialization_roundtrip() {
        let event = CloseEvent::SummaryVerified {
            participant_did: "did:scp:alice".to_owned(),
            verified_at: 1_700_000_100,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: CloseEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, event);
    }

    #[test]
    fn close_event_keys_destroyed_serialization_roundtrip() {
        let event = CloseEvent::KeysDestroyed {
            attestation_level: KeyDestructionLevel::SoftwareOnly,
            destroyed_at: 1_700_000_300,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: CloseEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, event);
    }

    #[test]
    fn close_event_full_close_completed_serialization_roundtrip() {
        let event = CloseEvent::FullCloseCompleted {
            completed_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: CloseEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, event);
    }

    // -----------------------------------------------------------------------
    // CloseOrchestrator -- Ephemeral close tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ephemeral_close_ttl_expired_destroys_keys() {
        let crypto = MockCryptoProvider::new();
        let orchestrator = CloseOrchestrator::new(&crypto);

        let result = orchestrator
            .initiate_close(
                "ctx-1",
                ContextCloseReason::TtlExpired,
                MemoryScope::Ephemeral,
                &["wss://relay.example.com".to_owned()],
                &[[0x01; 32]],
                KeyDestructionLevel::SoftwareOnly,
                2,
                None,
                1_700_000_000,
            )
            .await;

        assert!(result.is_ok());
        let action = result.unwrap();
        match action {
            CloseAction::KeysDestroyed {
                reason,
                result,
                event,
            } => {
                assert_eq!(reason, ContextCloseReason::TtlExpired);
                assert!(result.attestation.mls_group_destroyed);
                assert!(result.attestation.sender_keys_destroyed);
                assert_eq!(result.deletion_requests.len(), 1);
                match event {
                    CloseEvent::KeysDestroyed {
                        attestation_level,
                        destroyed_at,
                    } => {
                        assert_eq!(attestation_level, KeyDestructionLevel::SoftwareOnly);
                        assert_eq!(destroyed_at, 1_700_000_000);
                    }
                    _ => panic!("expected KeysDestroyed event"),
                }
            }
            _ => panic!("expected KeysDestroyed action for Ephemeral scope"),
        }
        assert!(crypto.mls_destroyed.load(Ordering::SeqCst));
        assert!(crypto.sender_key_destroyed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn ephemeral_close_governance_closed_destroys_keys() {
        let crypto = MockCryptoProvider::new();
        let orchestrator = CloseOrchestrator::new(&crypto);

        let result = orchestrator
            .initiate_close(
                "ctx-2",
                ContextCloseReason::GovernanceClosed,
                MemoryScope::Ephemeral,
                &[],
                &[],
                KeyDestructionLevel::HardwareAttested,
                3,
                None,
                1_700_000_000,
            )
            .await;

        assert!(result.is_ok());
        match result.unwrap() {
            CloseAction::KeysDestroyed { reason, .. } => {
                assert_eq!(reason, ContextCloseReason::GovernanceClosed);
            }
            _ => panic!("expected KeysDestroyed action"),
        }
    }

    #[tokio::test]
    async fn ephemeral_close_all_members_left_destroys_keys() {
        let crypto = MockCryptoProvider::new();
        let orchestrator = CloseOrchestrator::new(&crypto);

        let result = orchestrator
            .initiate_close(
                "ctx-3",
                ContextCloseReason::AllMembersLeft,
                MemoryScope::Ephemeral,
                &[],
                &[],
                KeyDestructionLevel::NoAttestation,
                0,
                None,
                1_700_000_000,
            )
            .await;

        assert!(result.is_ok());
        match result.unwrap() {
            CloseAction::KeysDestroyed { reason, .. } => {
                assert_eq!(reason, ContextCloseReason::AllMembersLeft);
            }
            _ => panic!("expected KeysDestroyed action"),
        }
    }

    #[tokio::test]
    async fn ephemeral_close_propagates_crypto_failure() {
        let crypto = MockCryptoProvider::failing_mls();
        let orchestrator = CloseOrchestrator::new(&crypto);

        let result = orchestrator
            .initiate_close(
                "ctx-1",
                ContextCloseReason::TtlExpired,
                MemoryScope::Ephemeral,
                &[],
                &[],
                KeyDestructionLevel::SoftwareOnly,
                2,
                None,
                1_700_000_000,
            )
            .await;

        assert!(result.is_err());
        match result {
            Err(ContextError::CryptoFailed(msg)) => {
                assert!(msg.contains("MLS destruction failed"));
            }
            _ => panic!("expected CryptoFailed error"),
        }
    }

    // -----------------------------------------------------------------------
    // CloseOrchestrator -- Summary close tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn summary_close_opens_verification_window() {
        let crypto = MockCryptoProvider::new();
        let orchestrator = CloseOrchestrator::new(&crypto);

        let result = orchestrator
            .initiate_close(
                "ctx-1",
                ContextCloseReason::GovernanceClosed,
                MemoryScope::Summary,
                &["wss://relay.example.com".to_owned()],
                &[[0x01; 32]],
                KeyDestructionLevel::SoftwareOnly,
                3,
                None,
                1_700_000_000,
            )
            .await;

        assert!(result.is_ok());
        match result.unwrap() {
            CloseAction::VerificationWindowOpened {
                reason,
                window,
                event,
            } => {
                assert_eq!(reason, ContextCloseReason::GovernanceClosed);
                assert_eq!(window.context_id(), "ctx-1");
                assert_eq!(window.opened_at(), 1_700_000_000);
                assert_eq!(
                    window.deadline(),
                    1_700_000_000 + DEFAULT_VERIFICATION_WINDOW_SECS
                );
                assert_eq!(window.member_count(), 3);
                match event {
                    CloseEvent::SummaryWindowOpened {
                        opened_at,
                        deadline,
                        member_count,
                    } => {
                        assert_eq!(opened_at, 1_700_000_000);
                        assert_eq!(deadline, 1_700_000_000 + DEFAULT_VERIFICATION_WINDOW_SECS);
                        assert_eq!(member_count, 3);
                    }
                    _ => panic!("expected SummaryWindowOpened event"),
                }
            }
            _ => panic!("expected VerificationWindowOpened action for Summary scope"),
        }
        // No keys should be destroyed yet.
        assert!(!crypto.mls_destroyed.load(Ordering::SeqCst));
        assert!(!crypto.sender_key_destroyed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn summary_close_custom_verification_window() {
        let crypto = MockCryptoProvider::new();
        let orchestrator = CloseOrchestrator::new(&crypto);

        let result = orchestrator
            .initiate_close(
                "ctx-1",
                ContextCloseReason::TtlExpired,
                MemoryScope::Summary,
                &[],
                &[],
                KeyDestructionLevel::SoftwareOnly,
                2,
                Some(600),
                1_700_000_000,
            )
            .await;

        assert!(result.is_ok());
        match result.unwrap() {
            CloseAction::VerificationWindowOpened { window, .. } => {
                assert_eq!(window.deadline(), 1_700_000_600);
            }
            _ => panic!("expected VerificationWindowOpened action"),
        }
    }

    #[tokio::test]
    async fn complete_summary_close_destroys_keys_after_window() {
        let crypto = MockCryptoProvider::new();
        let orchestrator = CloseOrchestrator::new(&crypto);

        let window = SummaryVerificationWindow::new("ctx-1".to_owned(), 1000, 300, 2);

        let result = orchestrator
            .complete_summary_close(
                &window,
                &["wss://relay.example.com".to_owned()],
                &[[0x01; 32]],
                KeyDestructionLevel::SoftwareOnly,
                1300,
            )
            .await;

        assert!(result.is_ok());
        let destruction_result = result.unwrap();
        assert!(destruction_result.attestation.mls_group_destroyed);
        assert!(destruction_result.attestation.sender_keys_destroyed);
        assert_eq!(destruction_result.deletion_requests.len(), 1);
        assert!(crypto.mls_destroyed.load(Ordering::SeqCst));
        assert!(crypto.sender_key_destroyed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn complete_summary_close_rejects_before_window_closes() {
        let crypto = MockCryptoProvider::new();
        let orchestrator = CloseOrchestrator::new(&crypto);

        let window = SummaryVerificationWindow::new("ctx-1".to_owned(), 1000, 300, 2);

        let result = orchestrator
            .complete_summary_close(&window, &[], &[], KeyDestructionLevel::SoftwareOnly, 1200)
            .await;

        assert!(result.is_err());
        match result {
            Err(ContextError::ContextNotActive) => {}
            _ => panic!("expected ContextNotActive error"),
        }
        assert!(!crypto.mls_destroyed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn complete_summary_close_propagates_crypto_failure() {
        let crypto = MockCryptoProvider::failing_mls();
        let orchestrator = CloseOrchestrator::new(&crypto);

        let window = SummaryVerificationWindow::new("ctx-1".to_owned(), 1000, 300, 2);

        let result = orchestrator
            .complete_summary_close(&window, &[], &[], KeyDestructionLevel::SoftwareOnly, 1300)
            .await;

        assert!(result.is_err());
        match result {
            Err(ContextError::CryptoFailed(msg)) => {
                assert!(msg.contains("MLS destruction failed"));
            }
            _ => panic!("expected CryptoFailed error"),
        }
    }

    // -----------------------------------------------------------------------
    // CloseOrchestrator -- Full close tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn full_close_preserves_keys_and_data() {
        let crypto = MockCryptoProvider::new();
        let orchestrator = CloseOrchestrator::new(&crypto);

        let result = orchestrator
            .initiate_close(
                "ctx-1",
                ContextCloseReason::GovernanceClosed,
                MemoryScope::Full,
                &["wss://relay.example.com".to_owned()],
                &[[0x01; 32]],
                KeyDestructionLevel::SoftwareOnly,
                3,
                None,
                1_700_000_000,
            )
            .await;

        assert!(result.is_ok());
        match result.unwrap() {
            CloseAction::Preserved { reason, event } => {
                assert_eq!(reason, ContextCloseReason::GovernanceClosed);
                match event {
                    CloseEvent::FullCloseCompleted { completed_at } => {
                        assert_eq!(completed_at, 1_700_000_000);
                    }
                    _ => panic!("expected FullCloseCompleted event"),
                }
            }
            _ => panic!("expected Preserved action for Full scope"),
        }
        // No keys should be destroyed.
        assert!(!crypto.mls_destroyed.load(Ordering::SeqCst));
        assert!(!crypto.sender_key_destroyed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn full_close_ttl_expired_preserves_data() {
        let crypto = MockCryptoProvider::new();
        let orchestrator = CloseOrchestrator::new(&crypto);

        let result = orchestrator
            .initiate_close(
                "ctx-1",
                ContextCloseReason::TtlExpired,
                MemoryScope::Full,
                &[],
                &[],
                KeyDestructionLevel::SoftwareOnly,
                1,
                None,
                1_700_000_000,
            )
            .await;

        assert!(result.is_ok());
        match result.unwrap() {
            CloseAction::Preserved { reason, .. } => {
                assert_eq!(reason, ContextCloseReason::TtlExpired);
            }
            _ => panic!("expected Preserved action"),
        }
    }

    #[tokio::test]
    async fn full_close_all_members_left_preserves_data() {
        let crypto = MockCryptoProvider::new();
        let orchestrator = CloseOrchestrator::new(&crypto);

        let result = orchestrator
            .initiate_close(
                "ctx-1",
                ContextCloseReason::AllMembersLeft,
                MemoryScope::Full,
                &[],
                &[],
                KeyDestructionLevel::SoftwareOnly,
                0,
                None,
                1_700_000_000,
            )
            .await;

        assert!(result.is_ok());
        match result.unwrap() {
            CloseAction::Preserved { reason, .. } => {
                assert_eq!(reason, ContextCloseReason::AllMembersLeft);
            }
            _ => panic!("expected Preserved action"),
        }
    }

    // -----------------------------------------------------------------------
    // Cross-cutting: all close reasons x all memory scopes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn all_reasons_ephemeral_scope_destroy_keys() {
        let reasons = [
            ContextCloseReason::TtlExpired,
            ContextCloseReason::GovernanceClosed,
            ContextCloseReason::AllMembersLeft,
        ];
        for reason in &reasons {
            let crypto = MockCryptoProvider::new();
            let orchestrator = CloseOrchestrator::new(&crypto);
            let result = orchestrator
                .initiate_close(
                    "ctx-matrix",
                    *reason,
                    MemoryScope::Ephemeral,
                    &[],
                    &[],
                    KeyDestructionLevel::SoftwareOnly,
                    2,
                    None,
                    1_700_000_000,
                )
                .await
                .unwrap();
            assert!(
                matches!(result, CloseAction::KeysDestroyed { .. }),
                "expected KeysDestroyed for {reason} + Ephemeral"
            );
            assert!(crypto.mls_destroyed.load(Ordering::SeqCst));
            assert!(crypto.sender_key_destroyed.load(Ordering::SeqCst));
        }
    }

    #[tokio::test]
    async fn all_reasons_summary_scope_open_verification_window() {
        let reasons = [
            ContextCloseReason::TtlExpired,
            ContextCloseReason::GovernanceClosed,
            ContextCloseReason::AllMembersLeft,
        ];
        for reason in &reasons {
            let crypto = MockCryptoProvider::new();
            let orchestrator = CloseOrchestrator::new(&crypto);
            let result = orchestrator
                .initiate_close(
                    "ctx-matrix",
                    *reason,
                    MemoryScope::Summary,
                    &[],
                    &[],
                    KeyDestructionLevel::SoftwareOnly,
                    2,
                    None,
                    1_700_000_000,
                )
                .await
                .unwrap();
            assert!(
                matches!(result, CloseAction::VerificationWindowOpened { .. }),
                "expected VerificationWindowOpened for {reason} + Summary"
            );
            assert!(!crypto.mls_destroyed.load(Ordering::SeqCst));
            assert!(!crypto.sender_key_destroyed.load(Ordering::SeqCst));
        }
    }

    #[tokio::test]
    async fn all_reasons_full_scope_preserve_data() {
        let reasons = [
            ContextCloseReason::TtlExpired,
            ContextCloseReason::GovernanceClosed,
            ContextCloseReason::AllMembersLeft,
        ];
        for reason in &reasons {
            let crypto = MockCryptoProvider::new();
            let orchestrator = CloseOrchestrator::new(&crypto);
            let result = orchestrator
                .initiate_close(
                    "ctx-matrix",
                    *reason,
                    MemoryScope::Full,
                    &[],
                    &[],
                    KeyDestructionLevel::SoftwareOnly,
                    2,
                    None,
                    1_700_000_000,
                )
                .await
                .unwrap();
            assert!(
                matches!(result, CloseAction::Preserved { .. }),
                "expected Preserved for {reason} + Full"
            );
            assert!(!crypto.mls_destroyed.load(Ordering::SeqCst));
            assert!(!crypto.sender_key_destroyed.load(Ordering::SeqCst));
        }
    }

    // -----------------------------------------------------------------------
    // End-to-end: Summary verification then key destruction
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn summary_close_end_to_end_verify_then_destroy() {
        let crypto = MockCryptoProvider::new();
        let orchestrator = CloseOrchestrator::new(&crypto);

        // Step 1: Initiate summary close.
        let action = orchestrator
            .initiate_close(
                "ctx-e2e",
                ContextCloseReason::GovernanceClosed,
                MemoryScope::Summary,
                &["wss://relay.example.com".to_owned()],
                &[[0xAB; 32]],
                KeyDestructionLevel::SoftwareOnly,
                2,
                Some(300),
                1000,
            )
            .await
            .unwrap();

        let mut window = match action {
            CloseAction::VerificationWindowOpened { window, .. } => window,
            _ => panic!("expected VerificationWindowOpened"),
        };

        // Step 2: Participants verify during the window.
        assert!(window.verify_summary("did:scp:alice", 1100).unwrap());
        assert!(window.verify_summary("did:scp:bob", 1200).unwrap());
        assert_eq!(window.verification_count(), 2);

        // Step 3: Window hasn't closed yet -- complete_summary_close should fail.
        let early_result = orchestrator
            .complete_summary_close(
                &window,
                &["wss://relay.example.com".to_owned()],
                &[[0xAB; 32]],
                KeyDestructionLevel::SoftwareOnly,
                1200,
            )
            .await;
        assert!(early_result.is_err());

        // Step 4: Window closes -- complete_summary_close succeeds.
        let result = orchestrator
            .complete_summary_close(
                &window,
                &["wss://relay.example.com".to_owned()],
                &[[0xAB; 32]],
                KeyDestructionLevel::SoftwareOnly,
                1300,
            )
            .await
            .unwrap();

        assert!(result.attestation.mls_group_destroyed);
        assert!(result.attestation.sender_keys_destroyed);
        assert_eq!(result.deletion_requests.len(), 1);
        assert!(crypto.mls_destroyed.load(Ordering::SeqCst));
        assert!(crypto.sender_key_destroyed.load(Ordering::SeqCst));
    }

    // -----------------------------------------------------------------------
    // Dispute resolution tests (#365)
    // -----------------------------------------------------------------------

    #[test]
    fn verify_then_close_succeeds_happy_path() {
        let mut window = SummaryVerificationWindow::new("ctx-dispute-1".to_owned(), 1000, 300, 2);
        window.verify_summary("did:dht:alice", 1100).unwrap();
        window.verify_summary("did:dht:bob", 1150).unwrap();
        assert_eq!(window.verification_count(), 2);
        assert_eq!(*window.state(), VerificationState::Verifying);
    }

    #[test]
    fn reject_transitions_to_disputed_state() {
        let mut window = SummaryVerificationWindow::new("ctx-dispute-2".to_owned(), 1000, 300, 2);
        let did = DID::from("did:dht:alice");
        window
            .reject(&did, "missing events".to_owned(), 1100)
            .unwrap();
        match window.state() {
            VerificationState::Disputed {
                rejector_did,
                reason,
            } => {
                assert_eq!(rejector_did, &did);
                assert_eq!(reason, "missing events");
            }
            _ => panic!("expected Disputed state"),
        }
    }

    #[test]
    fn reject_after_window_closed_fails() {
        let mut window = SummaryVerificationWindow::new("ctx-dispute-3".to_owned(), 1000, 300, 2);
        let did = DID::from("did:dht:alice");
        let result = window.reject(&did, "too late".to_owned(), 1400);
        assert!(result.is_err());
    }

    #[test]
    fn reject_while_already_disputed_fails() {
        let mut window = SummaryVerificationWindow::new("ctx-dispute-4".to_owned(), 1000, 300, 2);
        let did1 = DID::from("did:dht:alice");
        let did2 = DID::from("did:dht:bob");
        window
            .reject(&did1, "bad summary".to_owned(), 1100)
            .unwrap();
        let result = window.reject(&did2, "also bad".to_owned(), 1100);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_dispute_proceed_transitions_to_resolved() {
        let mut window = SummaryVerificationWindow::new("ctx-dispute-5".to_owned(), 1000, 300, 2);
        let did = DID::from("did:dht:alice");
        window.reject(&did, "bad".to_owned(), 1100).unwrap();
        window
            .resolve_dispute(DisputeAction::Proceed, 1150)
            .unwrap();
        match window.state() {
            VerificationState::Resolved { action } => {
                assert_eq!(*action, DisputeAction::Proceed);
            }
            _ => panic!("expected Resolved state"),
        }
    }

    #[test]
    fn resolve_dispute_revise_resets_window() {
        let mut window = SummaryVerificationWindow::new("ctx-dispute-6".to_owned(), 1000, 300, 2);
        let did = DID::from("did:dht:alice");
        window.verify_summary("did:dht:bob", 1050).unwrap();
        assert_eq!(window.verification_count(), 1);

        window.reject(&did, "wrong".to_owned(), 1100).unwrap();
        window
            .resolve_dispute(
                DisputeAction::Revise {
                    new_summary: "revised summary".to_owned(),
                },
                1200,
            )
            .unwrap();

        // Should be back to Verifying with cleared votes and extended deadline.
        assert_eq!(*window.state(), VerificationState::Verifying);
        assert_eq!(window.verification_count(), 0);
        // Deadline should be 1200 + 300 = 1500 (original duration re-applied).
        assert_eq!(window.deadline(), 1500);
    }

    #[test]
    fn resolve_dispute_when_not_disputed_fails() {
        let mut window = SummaryVerificationWindow::new("ctx-dispute-7".to_owned(), 1000, 300, 2);
        let result = window.resolve_dispute(DisputeAction::Proceed, 1100);
        assert!(result.is_err());
    }

    #[test]
    fn ttl_expiry_with_proceed_policy_returns_true() {
        let mut window = SummaryVerificationWindow::new("ctx-ttl-1".to_owned(), 1000, 300, 2);
        assert!(window.handle_ttl_expiry(1300));
    }

    #[test]
    fn ttl_expiry_with_extend_policy_extends_deadline() {
        let mut window = SummaryVerificationWindow::with_policy(
            "ctx-ttl-2".to_owned(),
            1000,
            300,
            2,
            IncompleteVerificationPolicy::ExtendWindow { duration_secs: 60 },
        );
        assert!(!window.handle_ttl_expiry(1300));
        assert_eq!(window.deadline(), 1360);
    }

    #[test]
    fn ttl_expiry_before_deadline_is_noop() {
        let mut window = SummaryVerificationWindow::new("ctx-ttl-3".to_owned(), 1000, 300, 2);
        assert!(!window.handle_ttl_expiry(1100));
    }

    #[test]
    fn reject_then_proceed_then_verify_succeeds() {
        // Full flow: reject -> admin proceeds -> verify succeeds.
        let mut window = SummaryVerificationWindow::new("ctx-flow-1".to_owned(), 1000, 300, 2);
        let did = DID::from("did:dht:alice");
        window.reject(&did, "incomplete".to_owned(), 1100).unwrap();
        window
            .resolve_dispute(DisputeAction::Proceed, 1150)
            .unwrap();
        // After Proceed resolution, window is in Resolved state.
        // Verification shouldn't be possible once resolved.
        assert!(matches!(
            *window.state(),
            VerificationState::Resolved { .. }
        ));
    }

    #[test]
    fn reject_then_revise_then_verify_then_close() {
        let mut window = SummaryVerificationWindow::new("ctx-flow-2".to_owned(), 1000, 300, 2);
        let did = DID::from("did:dht:alice");
        window
            .reject(&did, "missing data".to_owned(), 1100)
            .unwrap();
        window
            .resolve_dispute(
                DisputeAction::Revise {
                    new_summary: "corrected".to_owned(),
                },
                1200,
            )
            .unwrap();

        // Now we're back in Verifying state, can verify the new summary.
        window.verify_summary("did:dht:alice", 1300).unwrap();
        window.verify_summary("did:dht:bob", 1350).unwrap();
        assert_eq!(window.verification_count(), 2);
        assert_eq!(*window.state(), VerificationState::Verifying);
    }
}
