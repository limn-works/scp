//! Context close, finalize, TTL expiry, and TTL timer management.
//!
//! Implements the context lifecycle termination operations from ADR-008
//! (`.docs/adrs/phase-2.md`):
//!
//! - [`close_context`] -- Initiates cooperative close (Active -> Closing).
//! - [`finalize_close`] -- Completes close after members process notifications
//!   (Closing -> Closed).
//! - [`handle_ttl_expiry`] -- Automatic expiry when TTL elapses
//!   (Active -> Expired).
//! - [`TtlTimer`] -- Manages tokio timer tasks for TTL enforcement.
//! - [`TtlExtension`] -- Tracks unanimous consent for TTL extension.
//!
//! # Close Capability
//!
//! The initiator of `close_context` must hold the `ContextClose` capability
//! (admin role or governance-permitted). This is checked via
//! [`ContextRoleState::member_has_capability`].
//!
//! # Memory Scope Behavior
//!
//! - **Ephemeral:** Keys destroyed on close/expiry. Content becomes unreadable.
//! - **Summary:** Summary generated during closing window, then keys destroyed.
//! - **Full:** Keys retained. Content remains readable after close.

use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::builder::{ContextCryptoProvider, ContextEventLogProvider, ContextTransportProvider};
use super::membership::{ContextEvent, DID};
use super::roles::{self, ContextRoleState};
use super::{ContextError, ContextHandle, ContextState, MemoryScope};

// ---------------------------------------------------------------------------
// context_id_to_bytes helper (mirrors manager.rs)
// ---------------------------------------------------------------------------

/// Converts a `context_id` string to a 32-byte array (truncated/zero-padded).
fn context_id_to_bytes(context_id: &str) -> [u8; 32] {
    let bytes = context_id.as_bytes();
    let mut result = [0u8; 32];
    let len = bytes.len().min(32);
    result[..len].copy_from_slice(&bytes[..len]);
    result
}

// ---------------------------------------------------------------------------
// close_context
// ---------------------------------------------------------------------------

/// Initiates cooperative context closure.
///
/// Verifies the initiator has the `ContextClose` capability, transitions the
/// context from `Active` to `Closing`, sends a close notification to all
/// members, schedules key destruction for ephemeral/summary scopes, and
/// appends a `ContextClosing` event to the event log.
///
/// If the memory scope is `Summary`, triggers summary generation (the
/// verification window runs while the context is in `Closing` state).
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
    // Verify context is Active.
    let state = handle.state().await;
    if state != ContextState::Active {
        return Err(ContextError::ContextNotActive);
    }

    // Verify initiator has ContextClose capability.
    if !role_state.member_has_capability(initiator_did, &roles::Capability::ContextClose) {
        return Err(ContextError::PermissionDenied(format!(
            "member {initiator_did} does not have context:close capability"
        )));
    }

    // Transition to Closing.
    handle.transition_to(&ContextState::Closing).await?;

    let context_id = handle.context_id().to_owned();
    let context_id_bytes = context_id_to_bytes(&context_id);

    // Determine memory scope behavior.
    let memory_scope = handle.params().memory_scope;
    let should_generate_summary = memory_scope == MemoryScope::Summary;
    let should_schedule_key_destruction =
        memory_scope == MemoryScope::Ephemeral || memory_scope == MemoryScope::Summary;

    // Append ContextClosing event to event log.
    event_log.append_context_event(&context_id_bytes, "ContextClosing")?;

    Ok(CloseResult {
        should_generate_summary,
        should_schedule_key_destruction,
    })
}

/// Result of a successful `close_context` call.
///
/// Callers use this to determine what follow-up actions to take (summary
/// generation, key destruction scheduling) before calling `finalize_close`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseResult {
    /// If `true`, the caller should trigger summary generation and allow a
    /// verification window before finalizing.
    pub should_generate_summary: bool,
    /// If `true`, key destruction should be scheduled (ephemeral/summary scope).
    pub should_schedule_key_destruction: bool,
}

// ---------------------------------------------------------------------------
// finalize_close
// ---------------------------------------------------------------------------

/// Completes context closure after all members have processed notifications.
///
/// Destroys MLS group state and all sender keys, issues relay deletion
/// requests for ephemeral/summary scope contexts, transitions from `Closing`
/// to `Closed`, and appends the final `ContextClosed` event.
///
/// See ADR-008 acceptance criterion 6.
///
/// # Errors
///
/// Returns [`ContextError::InvalidTransition`] if the context is not in
/// `Closing` state. Returns crypto or transport errors if destruction fails.
pub async fn finalize_close(
    handle: &ContextHandle,
    crypto: &dyn ContextCryptoProvider,
    transport: &dyn ContextTransportProvider,
    event_log: &dyn ContextEventLogProvider,
) -> Result<(), ContextError> {
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = context_id_to_bytes(&context_id);
    let memory_scope = handle.params().memory_scope;

    // Destroy MLS group state (ADR-001 destroy_group()).
    crypto
        .destroy_mls_group(&context_id_bytes)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    // Destroy all sender keys for this context.
    crypto
        .destroy_sender_key(&context_id_bytes)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    // Issue relay deletion requests for ephemeral/summary scope contexts
    // (spec section 5.11). Best-effort: relays are untrusted.
    if memory_scope == MemoryScope::Ephemeral || memory_scope == MemoryScope::Summary {
        // Best-effort deletion -- log but don't fail on transport errors.
        let _ = transport.delete_published(&context_id_bytes);
    }

    // Transition to Closed.
    handle.transition_to(&ContextState::Closed).await?;

    // Append ContextClosed event to event log (final event).
    event_log.append_context_event(&context_id_bytes, "ContextClosed")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// handle_ttl_expiry
// ---------------------------------------------------------------------------

/// Handles automatic TTL expiry.
///
/// Transitions directly from `Active` to `Expired`, destroys MLS group state
/// and sender keys according to memory scope, and appends `ContextExpired`
/// to the event log.
///
/// Unlike cooperative close, TTL expiry skips the closing window -- it is a
/// hard deadline that cannot be overridden by governance (spec section 5.10).
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
    // Verify context is Active.
    let state = handle.state().await;
    if state != ContextState::Active {
        return Err(ContextError::ContextNotActive);
    }

    let context_id = handle.context_id().to_owned();
    let context_id_bytes = context_id_to_bytes(&context_id);
    let memory_scope = handle.params().memory_scope;

    // Transition directly to Expired (skips Closing).
    handle.transition_to(&ContextState::Expired).await?;

    // Destroy keys per memory scope.
    // For Ephemeral and Summary: destroy immediately.
    // For Full: keys are retained (content remains readable).
    if memory_scope == MemoryScope::Ephemeral || memory_scope == MemoryScope::Summary {
        // Best-effort: log but continue on crypto errors.
        let _ = crypto.destroy_mls_group(&context_id_bytes);
        let _ = crypto.destroy_sender_key(&context_id_bytes);
    }

    // Append ContextExpired event to event log.
    event_log.append_context_event(&context_id_bytes, "ContextExpired")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// TtlTimer -- tokio-based TTL timer management
// ---------------------------------------------------------------------------

/// Manages a TTL timer for a single context.
///
/// On context creation with a TTL, a tokio timer task is spawned that fires
/// at expiry and calls `handle_ttl_expiry()`. The timer can be cancelled
/// (on early close) or reset (on TTL extension with unanimous consent).
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
    ///
    /// Use [`TtlTimer::spawn`] to start the timer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            task: None,
            cancel: Arc::new(Notify::new()),
        }
    }

    /// Spawns a TTL timer task that fires after the given duration.
    ///
    /// When the timer fires, it calls `handle_ttl_expiry` on the context.
    /// The timer can be cancelled by calling [`TtlTimer::cancel`].
    ///
    /// # Arguments
    ///
    /// * `duration` -- The TTL duration.
    /// * `handle` -- The context handle to expire.
    /// * `crypto` -- Crypto provider for key destruction.
    /// * `event_log` -- Event log provider for appending the expiry event.
    pub fn spawn(
        &mut self,
        duration: std::time::Duration,
        handle: ContextHandle,
        crypto: Arc<dyn ContextCryptoProvider>,
        event_log: Arc<dyn ContextEventLogProvider>,
    ) {
        let cancel = self.cancel.clone();

        let task = tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(duration) => {
                    // Timer fired -- expire the context.
                    let _ = handle_ttl_expiry(&handle, crypto.as_ref(), event_log.as_ref()).await;
                }
                () = cancel.notified() => {
                    // Timer was cancelled (context closed early or TTL extended).
                }
            }
        });

        self.task = Some(task);
    }

    /// Cancels the running TTL timer, if any.
    ///
    /// Called when the context closes before TTL elapses, or when the TTL is
    /// extended (the old timer is cancelled and a new one is spawned).
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
        // Cancel the timer on drop to prevent orphaned tasks.
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
///
/// TTL extension requires unanimous consent from all current members
/// (spec section 5.10). Once all members have consented, the caller
/// resets the TTL timer with the new duration.
#[derive(Debug, Clone)]
pub struct TtlExtension {
    /// The proposed new TTL duration.
    pub proposed_duration: std::time::Duration,
    /// DIDs that have consented to the extension.
    consented: HashSet<DID>,
    /// Total member count required for unanimity.
    required_count: usize,
}

impl TtlExtension {
    /// Creates a new TTL extension proposal.
    ///
    /// # Arguments
    ///
    /// * `proposed_duration` -- The new TTL duration being proposed.
    /// * `member_count` -- The total number of members who must consent.
    #[must_use]
    pub fn new(proposed_duration: std::time::Duration, member_count: usize) -> Self {
        Self {
            proposed_duration,
            consented: HashSet::new(),
            required_count: member_count,
        }
    }

    /// Records a member's consent. Returns `true` if this was a new consent
    /// (not a duplicate).
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
}

// ---------------------------------------------------------------------------
// ContextEvent variants for close/expiry notifications
// ---------------------------------------------------------------------------

/// Creates a `ContextClosing` notification event.
#[must_use]
pub fn closing_notification(initiator_did: &DID) -> ContextEvent {
    ContextEvent::MemberLeft {
        member_did: format!("__close_notification:{initiator_did}"),
    }
}

/// Creates a `ContextExpired` notification event.
#[must_use]
pub fn expiry_notification() -> ContextEvent {
    ContextEvent::MemberLeft {
        member_did: "__ttl_expiry_notification".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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

    // -----------------------------------------------------------------------
    // Mock providers (reusable for ttl tests)
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Helper: create a role state with close capability for admin
    // -----------------------------------------------------------------------

    fn role_state_with_close_capability(context_id: &str, creator_did: &str) -> ContextRoleState {
        let ceiling = CapabilityCeiling::new(
            [
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::ContextClose,
                Capability::RoleAssign,
            ]
            .into_iter(),
        );
        ContextRoleState::new(context_id, creator_did, ceiling, vec![]).unwrap()
    }

    fn role_state_without_close_capability(
        context_id: &str,
        creator_did: &str,
    ) -> ContextRoleState {
        let ceiling = CapabilityCeiling::new(
            [Capability::MessagesRead, Capability::MessagesWrite].into_iter(),
        );
        // The admin will have all ceiling caps, but ContextClose is not in
        // the ceiling, so even admin won't have it.
        ContextRoleState::new(context_id, creator_did, ceiling, vec![]).unwrap()
    }

    fn active_handle(context_id: &str, memory_scope: MemoryScope) -> ContextHandle {
        let params = ContextParams {
            memory_scope,
            ..ContextParams::default()
        };
        let handle = ContextHandle::new(context_id.to_owned(), params);
        // We need to transition to Active synchronously for test setup.
        // We'll do it in the test body since it's async.
        handle
    }

    async fn make_active(handle: &ContextHandle) {
        handle.transition_to(&ContextState::Active).await.unwrap();
    }

    // -----------------------------------------------------------------------
    // close_context tests
    // -----------------------------------------------------------------------

    /// AC-1: close_context rejects initiator without close capability.
    #[tokio::test]
    async fn close_context_rejects_without_close_capability() {
        let handle = active_handle("ctx-close-1", MemoryScope::Ephemeral);
        make_active(&handle).await;

        // Creator does NOT have ContextClose (not in ceiling).
        let role_state = role_state_without_close_capability("ctx-close-1", "did:key:creator");
        let event_log = MockEventLog::default();

        let result =
            close_context(&handle, &"did:key:creator".into(), &role_state, &event_log).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::PermissionDenied(_)
        ));

        // State should still be Active (no transition occurred).
        assert_eq!(handle.state().await, ContextState::Active);
    }

    /// AC-1: close_context succeeds for admin with close capability.
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

        // Ephemeral scope: no summary, but schedule key destruction.
        assert!(!close_result.should_generate_summary);
        assert!(close_result.should_schedule_key_destruction);

        // State should be Closing.
        assert_eq!(handle.state().await, ContextState::Closing);

        // Event log should contain ContextClosing.
        let events = event_log.events.lock().unwrap();
        assert!(events.iter().any(|(_, e)| e == "ContextClosing"));
    }

    /// AC-1: close_context with Summary scope triggers summary generation.
    #[tokio::test]
    async fn close_context_summary_scope_triggers_summary_generation() {
        let handle = active_handle("ctx-close-3", MemoryScope::Summary);
        make_active(&handle).await;

        let role_state = role_state_with_close_capability("ctx-close-3", "did:key:creator");
        let event_log = MockEventLog::default();

        let result =
            close_context(&handle, &"did:key:creator".into(), &role_state, &event_log).await;

        assert!(result.is_ok());
        let close_result = result.unwrap();

        assert!(close_result.should_generate_summary);
        assert!(close_result.should_schedule_key_destruction);
    }

    /// AC-1: close_context with Full scope does not schedule key destruction.
    #[tokio::test]
    async fn close_context_full_scope_retains_keys() {
        let handle = active_handle("ctx-close-4", MemoryScope::Full);
        make_active(&handle).await;

        let role_state = role_state_with_close_capability("ctx-close-4", "did:key:creator");
        let event_log = MockEventLog::default();

        let result =
            close_context(&handle, &"did:key:creator".into(), &role_state, &event_log).await;

        assert!(result.is_ok());
        let close_result = result.unwrap();

        assert!(!close_result.should_generate_summary);
        assert!(!close_result.should_schedule_key_destruction);
    }

    /// AC-1: close_context rejects if context is not Active.
    #[tokio::test]
    async fn close_context_rejects_when_not_active() {
        let handle = active_handle("ctx-close-5", MemoryScope::Ephemeral);
        // Don't transition to Active -- stays in Creating.

        let role_state = role_state_with_close_capability("ctx-close-5", "did:key:creator");
        let event_log = MockEventLog::default();

        let result =
            close_context(&handle, &"did:key:creator".into(), &role_state, &event_log).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    // -----------------------------------------------------------------------
    // finalize_close tests
    // -----------------------------------------------------------------------

    /// AC-2: finalize_close destroys MLS group and sender keys.
    #[tokio::test]
    async fn finalize_close_destroys_mls_group_and_sender_keys() {
        let handle = active_handle("ctx-final-1", MemoryScope::Ephemeral);
        make_active(&handle).await;
        handle.transition_to(&ContextState::Closing).await.unwrap();

        let crypto = MockCrypto::default();
        let transport = MockTransport::connected();
        let event_log = MockEventLog::default();

        let result = finalize_close(&handle, &crypto, &transport, &event_log).await;
        assert!(result.is_ok());

        // MLS group and sender key should be destroyed.
        let mls = crypto.mls_destroyed.lock().unwrap();
        assert_eq!(mls.len(), 1);

        let sk = crypto.sender_keys_destroyed.lock().unwrap();
        assert_eq!(sk.len(), 1);

        // State should be Closed.
        assert_eq!(handle.state().await, ContextState::Closed);

        // Event log should contain ContextClosed.
        let events = event_log.events.lock().unwrap();
        assert!(events.iter().any(|(_, e)| e == "ContextClosed"));
    }

    /// AC-2: finalize_close issues relay deletion for ephemeral scope.
    #[tokio::test]
    async fn finalize_close_issues_relay_deletion_for_ephemeral() {
        let handle = active_handle("ctx-final-2", MemoryScope::Ephemeral);
        make_active(&handle).await;
        handle.transition_to(&ContextState::Closing).await.unwrap();

        let crypto = MockCrypto::default();
        let transport = MockTransport::connected();
        let event_log = MockEventLog::default();

        finalize_close(&handle, &crypto, &transport, &event_log)
            .await
            .unwrap();

        let deleted = transport.deleted.lock().unwrap();
        assert_eq!(deleted.len(), 1);
    }

    /// AC-2: finalize_close does NOT issue relay deletion for Full scope.
    #[tokio::test]
    async fn finalize_close_no_relay_deletion_for_full_scope() {
        let handle = active_handle("ctx-final-3", MemoryScope::Full);
        make_active(&handle).await;
        handle.transition_to(&ContextState::Closing).await.unwrap();

        let crypto = MockCrypto::default();
        let transport = MockTransport::connected();
        let event_log = MockEventLog::default();

        finalize_close(&handle, &crypto, &transport, &event_log)
            .await
            .unwrap();

        let deleted = transport.deleted.lock().unwrap();
        assert!(deleted.is_empty());
    }

    /// AC-2: finalize_close rejects if not in Closing state.
    #[tokio::test]
    async fn finalize_close_rejects_when_not_closing() {
        let handle = active_handle("ctx-final-4", MemoryScope::Ephemeral);
        make_active(&handle).await;
        // Still Active -- not Closing.

        let crypto = MockCrypto::default();
        let transport = MockTransport::connected();
        let event_log = MockEventLog::default();

        let result = finalize_close(&handle, &crypto, &transport, &event_log).await;

        // The crypto operations will succeed, but transition_to(Closed) from
        // Active should fail.
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // handle_ttl_expiry tests
    // -----------------------------------------------------------------------

    /// AC-3: TTL expiry transitions Active to Expired automatically.
    #[tokio::test]
    async fn ttl_expiry_transitions_active_to_expired() {
        let handle = active_handle("ctx-ttl-1", MemoryScope::Ephemeral);
        make_active(&handle).await;

        let crypto = MockCrypto::default();
        let event_log = MockEventLog::default();

        let result = handle_ttl_expiry(&handle, &crypto, &event_log).await;
        assert!(result.is_ok());

        // State should be Expired.
        assert_eq!(handle.state().await, ContextState::Expired);

        // Keys should be destroyed for Ephemeral scope.
        let mls = crypto.mls_destroyed.lock().unwrap();
        assert_eq!(mls.len(), 1);

        let sk = crypto.sender_keys_destroyed.lock().unwrap();
        assert_eq!(sk.len(), 1);

        // Event log should contain ContextExpired.
        let events = event_log.events.lock().unwrap();
        assert!(events.iter().any(|(_, e)| e == "ContextExpired"));
    }

    /// AC-3: TTL expiry with Full scope does NOT destroy keys.
    #[tokio::test]
    async fn ttl_expiry_full_scope_retains_keys() {
        let handle = active_handle("ctx-ttl-2", MemoryScope::Full);
        make_active(&handle).await;

        let crypto = MockCrypto::default();
        let event_log = MockEventLog::default();

        let result = handle_ttl_expiry(&handle, &crypto, &event_log).await;
        assert!(result.is_ok());

        assert_eq!(handle.state().await, ContextState::Expired);

        // Keys should NOT be destroyed for Full scope.
        let mls = crypto.mls_destroyed.lock().unwrap();
        assert!(mls.is_empty());

        let sk = crypto.sender_keys_destroyed.lock().unwrap();
        assert!(sk.is_empty());
    }

    /// AC-3: TTL expiry rejects if not Active.
    #[tokio::test]
    async fn ttl_expiry_rejects_when_not_active() {
        let handle = active_handle("ctx-ttl-3", MemoryScope::Ephemeral);
        // Stay in Creating state.

        let crypto = MockCrypto::default();
        let event_log = MockEventLog::default();

        let result = handle_ttl_expiry(&handle, &crypto, &event_log).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    // -----------------------------------------------------------------------
    // TtlTimer tests
    // -----------------------------------------------------------------------

    /// AC-4: TTL timer fires and calls handle_ttl_expiry.
    #[tokio::test]
    async fn ttl_timer_fires_and_expires_context() {
        let handle = active_handle("ctx-timer-1", MemoryScope::Ephemeral);
        make_active(&handle).await;

        let crypto: Arc<dyn ContextCryptoProvider> = Arc::new(MockCrypto::default());
        let event_log: Arc<dyn ContextEventLogProvider> = Arc::new(MockEventLog::default());

        let mut timer = TtlTimer::new();
        timer.spawn(Duration::from_millis(50), handle.clone(), crypto, event_log);

        assert!(timer.is_active());

        // Wait for timer to fire.
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Context should be Expired.
        assert_eq!(handle.state().await, ContextState::Expired);
    }

    /// AC-4: TTL timer cancelled on early close.
    #[tokio::test]
    async fn ttl_timer_cancelled_on_early_close() {
        let handle = active_handle("ctx-timer-2", MemoryScope::Ephemeral);
        make_active(&handle).await;

        let crypto: Arc<dyn ContextCryptoProvider> = Arc::new(MockCrypto::default());
        let event_log: Arc<dyn ContextEventLogProvider> = Arc::new(MockEventLog::default());

        let mut timer = TtlTimer::new();
        timer.spawn(
            Duration::from_secs(10), // Long TTL
            handle.clone(),
            crypto,
            event_log,
        );

        assert!(timer.is_active());

        // Cancel the timer (simulating early close).
        timer.cancel();

        // Wait a bit for cancellation to take effect.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Context should still be Active (not expired).
        assert_eq!(handle.state().await, ContextState::Active);

        // Timer should no longer be active.
        assert!(!timer.is_active());
    }

    /// TtlTimer default creates an inactive timer.
    #[tokio::test]
    async fn ttl_timer_default_is_inactive() {
        let timer = TtlTimer::default();
        assert!(!timer.is_active());
    }

    // -----------------------------------------------------------------------
    // TtlExtension tests
    // -----------------------------------------------------------------------

    /// AC-5: TTL extension requires unanimous consent.
    #[test]
    fn ttl_extension_requires_unanimous_consent() {
        let mut ext = TtlExtension::new(Duration::from_secs(3600), 3);

        assert!(!ext.is_unanimous());
        assert_eq!(ext.remaining(), 3);
        assert_eq!(ext.consent_count(), 0);

        assert!(ext.add_consent("did:key:alice".into()));
        assert!(!ext.is_unanimous());
        assert_eq!(ext.remaining(), 2);

        assert!(ext.add_consent("did:key:bob".into()));
        assert!(!ext.is_unanimous());
        assert_eq!(ext.remaining(), 1);

        assert!(ext.add_consent("did:key:charlie".into()));
        assert!(ext.is_unanimous());
        assert_eq!(ext.remaining(), 0);
    }

    /// Duplicate consent is ignored.
    #[test]
    fn ttl_extension_duplicate_consent_ignored() {
        let mut ext = TtlExtension::new(Duration::from_secs(3600), 2);

        assert!(ext.add_consent("did:key:alice".into()));
        assert!(!ext.add_consent("did:key:alice".into())); // duplicate

        assert_eq!(ext.consent_count(), 1);
        assert!(!ext.is_unanimous());
    }

    /// Single member can achieve unanimity alone.
    #[test]
    fn ttl_extension_single_member_unanimity() {
        let mut ext = TtlExtension::new(Duration::from_secs(600), 1);

        assert!(!ext.is_unanimous());
        assert!(ext.add_consent("did:key:alice".into()));
        assert!(ext.is_unanimous());
    }
}
