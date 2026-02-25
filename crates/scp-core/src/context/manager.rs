//! Context Manager -- central coordinator for context lifecycle.
//!
//! The [`ContextManager`] owns the provider implementations and exposes the
//! public API for context creation, membership, and messaging. It delegates
//! to [`builder::create_context`] for the two-phase commit flow.
//!
//! Providers are injected through the constructor, making the manager fully
//! testable with mock implementations. See ADR-008 in
//! `.docs/adrs/phase-2.md` for the full context lifecycle specification.

use std::collections::HashMap;
use std::sync::Mutex;

use super::builder::{
    ContextCreationError, ContextCryptoProvider, ContextEventLogProvider, ContextTransportProvider,
    create_context as builder_create_context,
};
use super::membership::{ContextEvent, DID, KeyPackage, MembershipState, ReceiveBuffer};
use super::roles::{self, Capability, CapabilityCeiling, ContextRoleState, RoleAssignment};
use super::ttl::{self, CloseResult, TtlExtension, TtlTimer};
use super::{ContextError, ContextHandle, ContextParams, ContextState};

// ---------------------------------------------------------------------------
// PerContextState -- internal per-context tracking
// ---------------------------------------------------------------------------

/// Internal state tracked by the manager for each context.
struct PerContextState {
    /// The context handle (retained to keep the Arc alive).
    #[allow(dead_code)]
    handle: ContextHandle,
    /// Member tracking.
    membership: MembershipState,
    /// Role state (ceiling, role definitions, assignments).
    role_state: ContextRoleState,
    /// Receive event buffer.
    receive_buffer: ReceiveBuffer,
    /// TTL timer management (SCP-021).
    ttl_timer: TtlTimer,
    /// Active TTL extension proposal, if any (SCP-021).
    #[allow(dead_code)]
    ttl_extension: Option<TtlExtension>,
}

// ---------------------------------------------------------------------------
// Helper: lock the contexts mutex
// ---------------------------------------------------------------------------

/// Locks the contexts `Mutex`, converting a `PoisonError` into a
/// [`ContextError::MembershipFailed`].
fn lock_contexts(
    mutex: &Mutex<HashMap<String, PerContextState>>,
) -> Result<std::sync::MutexGuard<'_, HashMap<String, PerContextState>>, ContextError> {
    mutex
        .lock()
        .map_err(|_| ContextError::MembershipFailed("contexts mutex poisoned".into()))
}

/// Locks the contexts `Mutex`, converting a `PoisonError` into a
/// [`ContextCreationError::CreationFailed`].
fn lock_contexts_creation(
    mutex: &Mutex<HashMap<String, PerContextState>>,
) -> Result<std::sync::MutexGuard<'_, HashMap<String, PerContextState>>, ContextCreationError> {
    mutex
        .lock()
        .map_err(|_| ContextCreationError::CreationFailed("contexts mutex poisoned".into()))
}

// ---------------------------------------------------------------------------
// ContextManager
// ---------------------------------------------------------------------------

/// Central coordinator for SCP context lifecycle operations.
///
/// `ContextManager` holds the injected providers for crypto, transport, and
/// event log operations and exposes the public API for context creation,
/// membership (join/leave), and messaging (send).
///
/// # Thread Safety
///
/// `ContextManager` is `Send + Sync` when all providers are `Send + Sync`
/// (which is enforced by the trait bounds). It is safe to share across
/// threads and async tasks. Per-context state is protected by a `Mutex`.
///
/// # Examples
///
/// ```ignore
/// let manager = ContextManager::new(crypto, transport, event_log);
/// let handle = manager.create_context("ctx-1".into(), params, "did:key:creator".into()).await?;
/// assert_eq!(handle.state().await, ContextState::Active);
/// ```
pub struct ContextManager {
    /// Provider for MLS group and sender key operations.
    crypto: Box<dyn ContextCryptoProvider>,
    /// Provider for relay connectivity and publication.
    transport: Box<dyn ContextTransportProvider>,
    /// Provider for event log initialisation and append.
    event_log: Box<dyn ContextEventLogProvider>,
    /// Per-context state, keyed by `context_id` string.
    contexts: Mutex<HashMap<String, PerContextState>>,
}

impl ContextManager {
    /// Creates a new `ContextManager` with the given providers.
    ///
    /// All providers are boxed trait objects, allowing any implementation
    /// to be injected (production implementations, test mocks, etc.).
    ///
    /// # Arguments
    ///
    /// * `crypto` -- Provider for MLS and sender key operations.
    /// * `transport` -- Provider for relay connectivity and publication.
    /// * `event_log` -- Provider for event log initialisation and append.
    #[must_use]
    pub fn new(
        crypto: Box<dyn ContextCryptoProvider>,
        transport: Box<dyn ContextTransportProvider>,
        event_log: Box<dyn ContextEventLogProvider>,
    ) -> Self {
        Self {
            crypto,
            transport,
            event_log,
            contexts: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a new SCP context with the two-phase commit pattern.
    ///
    /// Delegates to [`builder::create_context`] which validates all
    /// preconditions (Phase 1), then executes creation steps with ordered
    /// rollback on failure (Phase 2).
    ///
    /// On success, registers the context with the manager for subsequent
    /// membership and messaging operations.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- Unique string identifier for the new context.
    /// * `params` -- Full context configuration ([`ContextParams`]).
    /// * `creator_did` -- The DID of the context creator.
    ///
    /// # Returns
    ///
    /// A [`ContextHandle`] in the `Active` state on success.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if any validation or execution step
    /// fails. The operation is atomic from the caller's perspective: on
    /// failure, no MLS group state, sender key material, or event log state
    /// persists.
    ///
    /// See ADR-008 acceptance criterion 2.
    pub async fn create_context(
        &self,
        context_id: String,
        params: ContextParams,
        creator_did: DID,
    ) -> Result<ContextHandle, ContextCreationError> {
        let handle = builder_create_context(
            context_id.clone(),
            params.clone(),
            self.crypto.as_ref(),
            self.transport.as_ref(),
            self.event_log.as_ref(),
        )
        .await?;

        // Build ceiling from params.
        let ceiling =
            CapabilityCeiling::new(params.ceiling.iter().map(Capability::from_param_capability));

        // Initialize role state with the creator as admin.
        let role_state = ContextRoleState::new(&context_id, &creator_did, ceiling, vec![])
            .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;

        // Initialize membership with the creator.
        let mut membership = MembershipState::new();
        let creator_tokens = role_state
            .assignments
            .get(&creator_did)
            .map(|a| a.tokens.clone())
            .unwrap_or_default();
        membership.add_member(creator_did, "admin".into(), creator_tokens);

        let per_context = PerContextState {
            handle: handle.clone(),
            membership,
            role_state,
            receive_buffer: ReceiveBuffer::new(),
            ttl_timer: TtlTimer::new(),
            ttl_extension: None,
        };

        lock_contexts_creation(&self.contexts)?.insert(context_id.clone(), per_context);

        // Spawn TTL timer if TTL is configured (SCP-021).
        if let Some(ttl_duration) = params.ttl {
            self.spawn_ttl_timer(&context_id, ttl_duration, handle.clone());
        }

        Ok(handle)
    }

    /// Creates a new SCP context without tracking membership state.
    ///
    /// This is the original `create_context` signature preserved for backward
    /// compatibility with existing tests. It delegates to the builder but does
    /// not register the context for membership operations.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if any validation or execution step
    /// fails.
    pub async fn create_context_bare(
        &self,
        context_id: String,
        params: ContextParams,
    ) -> Result<ContextHandle, ContextCreationError> {
        builder_create_context(
            context_id,
            params,
            self.crypto.as_ref(),
            self.transport.as_ref(),
            self.event_log.as_ref(),
        )
        .await
    }

    /// Joins a member to a context.
    ///
    /// Validates the joiner's key package, adds to MLS group (ADR-001),
    /// distributes sender key bundle (ADR-007), assigns the default role,
    /// issues UCAN tokens, and appends a `MemberJoined` event.
    ///
    /// See ADR-008 acceptance criterion 3.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if:
    /// - The context is not in `Active` state.
    /// - The key package is invalid.
    /// - Any crypto or event log operation fails.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn join_context(
        &self,
        handle: &ContextHandle,
        key_package: KeyPackage,
    ) -> Result<(), ContextError> {
        // Verify context is Active.
        let state = handle.state().await;
        if state != ContextState::Active {
            return Err(ContextError::ContextNotActive);
        }

        let context_id = handle.context_id().to_owned();
        let context_id_bytes = context_id_to_bytes(&context_id);
        let member_did = key_package.owner_did.clone();

        // Validate key package.
        self.crypto.validate_key_package(&member_did)?;

        // Add to MLS group.
        self.crypto.add_member(&context_id_bytes, &member_did)?;

        // Distribute sender key bundle.
        self.crypto
            .distribute_sender_key(&context_id_bytes, &member_did)?;

        // Assign role and issue UCAN tokens.
        {
            let mut contexts = lock_contexts(&self.contexts)?;
            let ctx = contexts
                .get_mut(&context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

            // Add member to role state.
            ctx.role_state.members.insert(member_did.clone());

            // Assign default "member" role.
            let creator_did = ctx.role_state.creator_did.clone();
            let tokens =
                roles::assign_role(&mut ctx.role_state, &member_did, "member", &creator_did)
                    .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

            // Add to membership tracking.
            ctx.membership
                .add_member(member_did.clone(), "member".into(), tokens);

            // Emit MemberJoined event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::MemberJoined {
                member_did: member_did.clone(),
                role_name: "member".into(),
            });
        }

        // Append MemberJoined event to event log.
        self.event_log
            .append_context_event(&context_id_bytes, "MemberJoined")?;

        Ok(())
    }

    /// Removes a member from a context.
    ///
    /// Removes from MLS group (ADR-001), removes sender keys, and appends
    /// a `MemberLeft` event. If the member count reaches zero, transitions
    /// the context to `Closing`.
    ///
    /// See ADR-008 acceptance criterion 4.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if:
    /// - The context is not in `Active` state.
    /// - The member is not found.
    /// - Any crypto or event log operation fails.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn leave_context(
        &self,
        handle: &ContextHandle,
        member_did: &DID,
    ) -> Result<(), ContextError> {
        // Verify context is Active.
        let state = handle.state().await;
        if state != ContextState::Active {
            return Err(ContextError::ContextNotActive);
        }

        let context_id = handle.context_id().to_owned();
        let context_id_bytes = context_id_to_bytes(&context_id);

        // Remove from MLS group.
        self.crypto.remove_member(&context_id_bytes, member_did)?;

        // Remove sender key.
        self.crypto
            .remove_member_sender_key(&context_id_bytes, member_did)?;

        // Update membership state and check if context should transition.
        let should_close = {
            let mut contexts = lock_contexts(&self.contexts)?;
            let ctx = contexts
                .get_mut(&context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

            if !ctx.membership.remove_member(member_did) {
                return Err(ContextError::MemberNotFound(member_did.clone()));
            }

            // Remove from role state.
            ctx.role_state.members.remove(member_did.as_str());
            ctx.role_state.assignments.remove(member_did.as_str());
            ctx.role_state
                .member_capabilities
                .remove(member_did.as_str());

            // Emit MemberLeft event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::MemberLeft {
                member_did: member_did.clone(),
            });

            ctx.membership.count() == 0
        };

        // Append MemberLeft event to event log.
        self.event_log
            .append_context_event(&context_id_bytes, "MemberLeft")?;

        // If member count reaches zero, transition to Closing.
        if should_close {
            handle.transition_to(&ContextState::Closing).await?;
        }

        Ok(())
    }

    /// Sends a message within a context.
    ///
    /// Validates the context is `Active`, validates the sender's UCAN for
    /// `messages:write` capability, assigns a per-sender monotonic SCP
    /// sequence number, encrypts the message (sender key + MLS + envelopes),
    /// sends via transport, and appends a `MessageSent` event.
    ///
    /// See ADR-008 acceptance criterion 8.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if:
    /// - The context is not in `Active` state.
    /// - The sender lacks `messages:write` capability.
    /// - Any crypto, transport, or event log operation fails.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn send_message(
        &self,
        handle: &ContextHandle,
        sender_did: &DID,
        payload: &[u8],
    ) -> Result<(), ContextError> {
        // Verify context is Active.
        let state = handle.state().await;
        if state != ContextState::Active {
            return Err(ContextError::ContextNotActive);
        }

        let context_id = handle.context_id().to_owned();
        let context_id_bytes = context_id_to_bytes(&context_id);

        // Validate UCAN for messages:write and assign sequence number.
        {
            let mut contexts = lock_contexts(&self.contexts)?;
            let ctx = contexts
                .get_mut(&context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

            // Check messages:write capability.
            if !ctx
                .role_state
                .member_has_capability(sender_did, &Capability::MessagesWrite)
            {
                return Err(ContextError::PermissionDenied(format!(
                    "member {sender_did} does not have messages:write capability"
                )));
            }

            // Assign per-sender monotonic sequence number.
            let seq = ctx
                .membership
                .next_sequence_number(sender_did)
                .ok_or_else(|| ContextError::MemberNotFound(sender_did.clone()))?;

            // Emit MessageSent event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::MessageSent {
                sender_did: sender_did.clone(),
                sequence_number: seq,
                payload: payload.to_vec(),
            });
        }

        // Encrypt: sender key (ADR-007) -> inner envelope (ADR-002) ->
        // MLS (ADR-001) -> outer envelope.
        let encrypted = self
            .crypto
            .encrypt_message(&context_id_bytes, sender_did, payload)?;

        // Send via transport.
        self.transport.send_message(&context_id_bytes, &encrypted)?;

        // Append MessageSent event to event log.
        self.event_log
            .append_context_event(&context_id_bytes, "MessageSent")?;

        Ok(())
    }

    /// Returns the current member count for a context.
    ///
    /// Returns `None` if the context is not registered with this manager.
    #[must_use]
    pub fn member_count(&self, context_id: &str) -> Option<usize> {
        lock_contexts(&self.contexts)
            .ok()?
            .get(context_id)
            .map(|ctx| ctx.membership.count())
    }

    /// Returns `true` if the given DID is a member of the specified context.
    #[must_use]
    pub fn is_member(&self, context_id: &str, did: &str) -> bool {
        lock_contexts(&self.contexts)
            .ok()
            .and_then(|contexts| {
                contexts
                    .get(context_id)
                    .map(|ctx| ctx.membership.contains(did))
            })
            .unwrap_or(false)
    }

    /// Returns all member DIDs for a context.
    #[must_use]
    pub fn member_dids(&self, context_id: &str) -> Vec<String> {
        lock_contexts(&self.contexts)
            .ok()
            .and_then(|contexts| {
                contexts
                    .get(context_id)
                    .map(|ctx| ctx.membership.member_dids().map(String::from).collect())
            })
            .unwrap_or_default()
    }

    /// Returns the role assignment for a specific member in a context.
    #[must_use]
    pub fn member_role(&self, context_id: &str, did: &str) -> Option<RoleAssignment> {
        lock_contexts(&self.contexts)
            .ok()?
            .get(context_id)
            .and_then(|ctx| ctx.role_state.assignments.get(did).cloned())
    }

    /// Drains all events from the receive buffer for a context.
    ///
    /// # Errors
    ///
    /// Returns an empty `Vec` if the context is not registered or the
    /// mutex is poisoned.
    pub fn drain_events(&self, context_id: &str) -> Vec<ContextEvent> {
        lock_contexts(&self.contexts)
            .ok()
            .and_then(|mut contexts| {
                contexts
                    .get_mut(context_id)
                    .map(|ctx| ctx.receive_buffer.drain())
            })
            .unwrap_or_default()
    }

    // -------------------------------------------------------------------
    // Close / Finalize / TTL Expiry (SCP-021)
    // -------------------------------------------------------------------

    /// Initiates cooperative context closure.
    ///
    /// Verifies the initiator has the `ContextClose` capability, transitions
    /// from `Active` to `Closing`, and appends a `ContextClosing` event.
    /// Cancels any active TTL timer for this context.
    ///
    /// See ADR-008 acceptance criterion 5.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotActive`] if the context is not
    /// `Active`. Returns [`ContextError::PermissionDenied`] if the
    /// initiator lacks the `ContextClose` capability.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn close_context(
        &self,
        handle: &ContextHandle,
        initiator_did: &DID,
    ) -> Result<CloseResult, ContextError> {
        let context_id = handle.context_id().to_owned();

        // Extract role_state for permission check (under lock).
        let role_state = {
            let contexts = lock_contexts(&self.contexts)?;
            let ctx = contexts
                .get(&context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            ctx.role_state.clone()
        };

        // Delegate to ttl::close_context for the actual logic.
        let result =
            ttl::close_context(handle, initiator_did, &role_state, self.event_log.as_ref()).await?;

        // Cancel TTL timer and emit close notification to receive buffer.
        {
            let mut contexts = lock_contexts(&self.contexts)?;
            if let Some(ctx) = contexts.get_mut(&context_id) {
                ctx.ttl_timer.cancel();
                ctx.receive_buffer.push(ContextEvent::MemberLeft {
                    member_did: format!("__close_notification:{initiator_did}"),
                });
            }
        }

        Ok(result)
    }

    /// Completes context closure.
    ///
    /// Destroys MLS group state and sender keys, issues relay deletion
    /// requests for ephemeral/summary scopes, transitions from `Closing`
    /// to `Closed`, and appends the final `ContextClosed` event.
    ///
    /// See ADR-008 acceptance criterion 6.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the context is not in `Closing` state
    /// or if destruction operations fail.
    pub async fn finalize_close(&self, handle: &ContextHandle) -> Result<(), ContextError> {
        ttl::finalize_close(
            handle,
            self.crypto.as_ref(),
            self.transport.as_ref(),
            self.event_log.as_ref(),
        )
        .await
    }

    /// Handles automatic TTL expiry.
    ///
    /// Transitions from `Active` to `Expired`, destroys keys per memory
    /// scope, and appends `ContextExpired` to the event log.
    ///
    /// See ADR-008 acceptance criterion 7.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotActive`] if the context is not
    /// `Active`.
    pub async fn handle_ttl_expiry(&self, handle: &ContextHandle) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();

        ttl::handle_ttl_expiry(handle, self.crypto.as_ref(), self.event_log.as_ref()).await?;

        // Emit expiry notification to receive buffer.
        {
            let mut contexts = lock_contexts(&self.contexts)?;
            if let Some(ctx) = contexts.get_mut(&context_id) {
                ctx.receive_buffer.push(ContextEvent::MemberLeft {
                    member_did: "__ttl_expiry_notification".to_owned(),
                });
            }
        }

        Ok(())
    }

    /// Proposes a TTL extension. Records consent from the given member.
    ///
    /// If all members have consented (unanimous), returns `true` indicating
    /// the extension was approved. The caller should then call
    /// [`reset_ttl_timer`](Self::reset_ttl_timer) with the new duration.
    ///
    /// See ADR-008 acceptance criterion 9 / spec section 5.10.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::MembershipFailed`] if the context is not
    /// registered. Returns [`ContextError::MemberNotFound`] if the member
    /// is not in the context.
    #[allow(clippy::significant_drop_tightening)]
    pub fn propose_ttl_extension(
        &self,
        context_id: &str,
        member_did: &DID,
        proposed_duration: std::time::Duration,
    ) -> Result<bool, ContextError> {
        let mut contexts = lock_contexts(&self.contexts)?;
        let ctx = contexts
            .get_mut(context_id)
            .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

        if !ctx.membership.contains(member_did) {
            return Err(ContextError::MemberNotFound(member_did.clone()));
        }

        let member_count = ctx.membership.count();

        // Initialize extension proposal if not already in progress.
        let extension = ctx
            .ttl_extension
            .get_or_insert_with(|| TtlExtension::new(proposed_duration, member_count));

        extension.add_consent(member_did.clone());

        Ok(extension.is_unanimous())
    }

    /// Resets the TTL timer after a successful unanimous extension.
    ///
    /// Cancels the old timer and spawns a new one with the given duration.
    /// Clears the extension proposal state.
    pub fn reset_ttl_timer(
        &self,
        context_id: &str,
        new_duration: std::time::Duration,
        handle: ContextHandle,
    ) {
        {
            let Ok(mut contexts) = lock_contexts(&self.contexts) else {
                return;
            };
            if let Some(ctx) = contexts.get_mut(context_id) {
                ctx.ttl_timer.cancel();
                ctx.ttl_extension = None;
            }
        }

        self.spawn_ttl_timer(context_id, new_duration, handle);
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    /// Spawns a TTL timer for the given context.
    ///
    /// The timer fires at the given duration and transitions the context
    /// to `Expired`. The timer task is stored in the per-context state
    /// for cancellation.
    #[allow(clippy::significant_drop_tightening)]
    fn spawn_ttl_timer(
        &self,
        context_id: &str,
        duration: std::time::Duration,
        handle: ContextHandle,
    ) {
        let context_id_owned = context_id.to_owned();
        let cancel = {
            let Ok(mut contexts) = lock_contexts(&self.contexts) else {
                return;
            };
            let Some(ctx) = contexts.get_mut(context_id) else {
                return;
            };
            ctx.ttl_timer.cancel.clone()
        };

        let task = tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(duration) => {
                    // Timer fired. Transition to Expired.
                    let _ = handle.transition_to(&ContextState::Expired).await;
                }
                () = cancel.notified() => {
                    // Timer was cancelled.
                }
            }
        });

        // Store the task handle.
        let Ok(mut contexts) = lock_contexts(&self.contexts) else {
            return;
        };
        if let Some(ctx) = contexts.get_mut(&context_id_owned) {
            ctx.ttl_timer.task = Some(task);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Uses the canonical SHA-256 context ID byte derivation.
/// Delegates to [`super::context_id_bytes`] to match builder.rs.
fn context_id_to_bytes(context_id: &str) -> [u8; 32] {
    super::context_id_bytes(context_id)
}

// Compile-time assertion that `ContextManager` is `Send + Sync`.
const fn _assert_send_sync() {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ContextManager>();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::context::{ContextMode, ContextState};

    // -----------------------------------------------------------------------
    // Reusable mock providers
    // -----------------------------------------------------------------------

    #[derive(Default)]
    struct MockCrypto {
        fail_create_mls: AtomicBool,
        fail_validate_key_package: AtomicBool,
        mls_created: Mutex<Vec<[u8; 32]>>,
        sender_keys_created: Mutex<Vec<[u8; 32]>>,
        broadcast_created: Mutex<Vec<[u8; 32]>>,
        mls_destroyed: Mutex<Vec<[u8; 32]>>,
        sender_keys_destroyed: Mutex<Vec<[u8; 32]>>,
        members_added: Mutex<Vec<String>>,
        members_removed: Mutex<Vec<String>>,
        sender_keys_distributed: Mutex<Vec<String>>,
        sender_keys_removed: Mutex<Vec<String>>,
        messages_encrypted: Mutex<Vec<Vec<u8>>>,
    }

    impl ContextCryptoProvider for MockCrypto {
        fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn create_mls_group(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            if self.fail_create_mls.load(Ordering::Relaxed) {
                return Err(ContextCreationError::CryptoFailed("mock failure".into()));
            }
            self.mls_created.lock().unwrap().push(*id);
            Ok(())
        }

        fn generate_sender_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.sender_keys_created.lock().unwrap().push(*id);
            Ok(())
        }

        fn init_broadcast_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.broadcast_created.lock().unwrap().push(*id);
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
            if self.fail_validate_key_package.load(Ordering::Relaxed) {
                return Err(ContextError::InvalidKeyPackage("mock invalid".into()));
            }
            Ok(())
        }

        fn add_member(&self, _context_id: &[u8; 32], member_did: &str) -> Result<(), ContextError> {
            self.members_added
                .lock()
                .unwrap()
                .push(member_did.to_owned());
            Ok(())
        }

        fn remove_member(
            &self,
            _context_id: &[u8; 32],
            member_did: &str,
        ) -> Result<(), ContextError> {
            self.members_removed
                .lock()
                .unwrap()
                .push(member_did.to_owned());
            Ok(())
        }

        fn distribute_sender_key(
            &self,
            _context_id: &[u8; 32],
            member_did: &str,
        ) -> Result<(), ContextError> {
            self.sender_keys_distributed
                .lock()
                .unwrap()
                .push(member_did.to_owned());
            Ok(())
        }

        fn remove_member_sender_key(
            &self,
            _context_id: &[u8; 32],
            member_did: &str,
        ) -> Result<(), ContextError> {
            self.sender_keys_removed
                .lock()
                .unwrap()
                .push(member_did.to_owned());
            Ok(())
        }

        fn encrypt_message(
            &self,
            _context_id: &[u8; 32],
            _sender_did: &str,
            payload: &[u8],
        ) -> Result<Vec<u8>, ContextError> {
            self.messages_encrypted
                .lock()
                .unwrap()
                .push(payload.to_vec());
            // Mock: return payload as-is (no real encryption).
            Ok(payload.to_vec())
        }
    }

    #[derive(Default)]
    struct MockTransport {
        connected: AtomicBool,
        published: Mutex<Vec<[u8; 32]>>,
        deleted: Mutex<Vec<[u8; 32]>>,
        messages_sent: Mutex<Vec<Vec<u8>>>,
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
            id: &[u8; 32],
            _params: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            self.published.lock().unwrap().push(*id);
            Ok(())
        }

        fn delete_published(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.deleted.lock().unwrap().push(*id);
            Ok(())
        }

        fn send_message(
            &self,
            _context_id: &[u8; 32],
            encrypted_payload: &[u8],
        ) -> Result<(), ContextError> {
            self.messages_sent
                .lock()
                .unwrap()
                .push(encrypted_payload.to_vec());
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockEventLog {
        inited: Mutex<Vec<[u8; 32]>>,
        events: Mutex<Vec<([u8; 32], String)>>,
        destroyed: Mutex<Vec<[u8; 32]>>,
    }

    impl ContextEventLogProvider for MockEventLog {
        fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.inited.lock().unwrap().push(*id);
            Ok(())
        }

        fn append_event(&self, id: &[u8; 32], event: &str) -> Result<(), ContextCreationError> {
            self.events.lock().unwrap().push((*id, event.to_owned()));
            Ok(())
        }

        fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.destroyed.lock().unwrap().push(*id);
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Helper: create a manager with default mocks and a registered context
    // -----------------------------------------------------------------------

    async fn setup_active_context() -> (ContextManager, ContextHandle) {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        let params = ContextParams {
            ceiling: vec![
                crate::context::params::Capability::new("messages:read"),
                crate::context::params::Capability::new("messages:write"),
                crate::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("test-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        (manager, handle)
    }

    // -----------------------------------------------------------------------
    // Context creation tests (backward compatibility)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn manager_create_context_encrypted_success() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        let handle = manager
            .create_context_bare("mgr-ctx-1".into(), ContextParams::default())
            .await;

        assert!(handle.is_ok());
        let handle = handle.unwrap();
        assert_eq!(handle.context_id(), "mgr-ctx-1");
        assert_eq!(handle.state().await, ContextState::Active);
    }

    #[tokio::test]
    async fn manager_create_context_broadcast_success() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            ..ContextParams::default()
        };

        let handle = manager
            .create_context_bare("mgr-ctx-bc".into(), params)
            .await;

        assert!(handle.is_ok());
        let handle = handle.unwrap();
        assert_eq!(handle.context_id(), "mgr-ctx-bc");
        assert_eq!(handle.state().await, ContextState::Active);
    }

    #[tokio::test]
    async fn manager_create_context_transport_disconnected() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::default()), // not connected
            Box::new(MockEventLog::default()),
        );

        let result = manager
            .create_context_bare("mgr-ctx-dc".into(), ContextParams::default())
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::TransportNotConnected
        ));
    }

    #[tokio::test]
    async fn manager_create_context_rollback_on_crypto_failure() {
        let crypto = MockCrypto::default();
        crypto.fail_create_mls.store(true, Ordering::Relaxed);

        let manager = ContextManager::new(
            Box::new(crypto),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        let result = manager
            .create_context_bare("mgr-ctx-fail".into(), ContextParams::default())
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::CryptoFailed(_)
        ));
    }

    #[tokio::test]
    async fn manager_preserves_params_on_handle() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            ..ContextParams::default()
        };

        let handle = manager
            .create_context_bare("mgr-ctx-p".into(), params.clone())
            .await
            .unwrap();

        assert_eq!(*handle.params(), params);
        assert_eq!(handle.params().mode, ContextMode::Broadcast);
    }

    // -----------------------------------------------------------------------
    // Join context tests
    // -----------------------------------------------------------------------

    /// Unit test: join adds member to MLS group and issues UCAN tokens.
    #[tokio::test]
    async fn join_adds_member_to_mls_group_and_issues_ucan_tokens() {
        let (manager, handle) = setup_active_context().await;

        let kp = KeyPackage {
            owner_did: "did:key:bob".into(),
        };

        let result = manager.join_context(&handle, kp).await;
        assert!(result.is_ok());

        // Verify member was added.
        assert!(manager.is_member("test-ctx", "did:key:bob"));
        assert_eq!(manager.member_count("test-ctx"), Some(2));

        // Verify UCAN tokens were issued.
        let role = manager.member_role("test-ctx", "did:key:bob");
        assert!(role.is_some());
        let role = role.unwrap();
        assert_eq!(role.role_name, "member");
        assert!(!role.tokens.is_empty());

        // Verify MemberJoined event was emitted.
        let events = manager.drain_events("test-ctx");
        let join_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ContextEvent::MemberJoined { .. }))
            .collect();
        assert_eq!(join_events.len(), 1);
    }

    #[tokio::test]
    async fn join_rejects_when_context_not_active() {
        let (manager, handle) = setup_active_context().await;

        // Transition to Closing.
        handle.transition_to(&ContextState::Closing).await.unwrap();

        let kp = KeyPackage {
            owner_did: "did:key:bob".into(),
        };

        let result = manager.join_context(&handle, kp).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    // -----------------------------------------------------------------------
    // Leave context tests
    // -----------------------------------------------------------------------

    /// Unit test: leave removes member and transitions to Closing when count
    /// reaches zero.
    #[tokio::test]
    async fn leave_removes_member_and_transitions_to_closing_when_empty() {
        let (manager, handle) = setup_active_context().await;

        // Remove the only member (creator).
        let result = manager
            .leave_context(&handle, &"did:key:creator".into())
            .await;
        assert!(result.is_ok());

        // Member count should be 0.
        assert_eq!(manager.member_count("test-ctx"), Some(0));
        assert!(!manager.is_member("test-ctx", "did:key:creator"));

        // Context should have transitioned to Closing.
        assert_eq!(handle.state().await, ContextState::Closing);

        // Verify MemberLeft event was emitted.
        let events = manager.drain_events("test-ctx");
        let left_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ContextEvent::MemberLeft { .. }))
            .collect();
        assert_eq!(left_events.len(), 1);
    }

    #[tokio::test]
    async fn leave_does_not_close_when_members_remain() {
        let (manager, handle) = setup_active_context().await;

        // Add a second member.
        let kp = KeyPackage {
            owner_did: "did:key:bob".into(),
        };
        manager.join_context(&handle, kp).await.unwrap();
        assert_eq!(manager.member_count("test-ctx"), Some(2));

        // Remove bob.
        manager.drain_events("test-ctx"); // Clear join event.
        let result = manager.leave_context(&handle, &"did:key:bob".into()).await;
        assert!(result.is_ok());

        // Context should still be Active (creator is still there).
        assert_eq!(handle.state().await, ContextState::Active);
        assert_eq!(manager.member_count("test-ctx"), Some(1));
    }

    #[tokio::test]
    async fn leave_rejects_when_context_not_active() {
        let (manager, handle) = setup_active_context().await;

        handle.transition_to(&ContextState::Closing).await.unwrap();

        let result = manager
            .leave_context(&handle, &"did:key:creator".into())
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    // -----------------------------------------------------------------------
    // Send message tests
    // -----------------------------------------------------------------------

    /// Unit test: `send_message` rejects when context is not Active.
    #[tokio::test]
    async fn send_message_rejects_when_context_not_active() {
        let (manager, handle) = setup_active_context().await;

        handle.transition_to(&ContextState::Closing).await.unwrap();

        let result = manager
            .send_message(&handle, &"did:key:creator".into(), b"hello")
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    /// Unit test: `send_message` validates UCAN before sending.
    #[tokio::test]
    async fn send_message_validates_ucan_before_sending() {
        let (manager, handle) = setup_active_context().await;

        // Try to send as a non-member -- should be denied.
        let result = manager
            .send_message(&handle, &"did:key:nonexistent".into(), b"hello")
            .await;
        assert!(result.is_err());

        // Should be either PermissionDenied or MemberNotFound.
        match result.unwrap_err() {
            ContextError::PermissionDenied(_) => {}
            ContextError::MemberNotFound(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_message_success_encrypts_and_sends() {
        let (manager, handle) = setup_active_context().await;

        let result = manager
            .send_message(&handle, &"did:key:creator".into(), b"hello world")
            .await;
        assert!(result.is_ok());

        // Verify MessageSent event was emitted.
        let events = manager.drain_events("test-ctx");
        let msg_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ContextEvent::MessageSent { .. }))
            .collect();
        assert_eq!(msg_events.len(), 1);

        if let ContextEvent::MessageSent {
            sender_did,
            sequence_number,
            payload,
        } = &msg_events[0]
        {
            assert_eq!(sender_did, "did:key:creator");
            assert_eq!(*sequence_number, 1);
            assert_eq!(payload, b"hello world");
        }
    }

    #[tokio::test]
    async fn send_message_assigns_monotonic_sequence_numbers() {
        let (manager, handle) = setup_active_context().await;

        for i in 1..=5u8 {
            manager
                .send_message(&handle, &"did:key:creator".into(), &[i])
                .await
                .unwrap();
        }

        let events = manager.drain_events("test-ctx");
        let seq_nums: Vec<u64> = events
            .iter()
            .filter_map(|e| {
                if let ContextEvent::MessageSent {
                    sequence_number, ..
                } = e
                {
                    Some(*sequence_number)
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(seq_nums, vec![1, 2, 3, 4, 5]);
    }

    // -----------------------------------------------------------------------
    // Member tracking tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn member_list_queries() {
        let (manager, handle) = setup_active_context().await;

        // Initially only creator.
        assert_eq!(manager.member_count("test-ctx"), Some(1));
        assert!(manager.is_member("test-ctx", "did:key:creator"));

        // Add members.
        for name in &["alice", "bob", "charlie"] {
            let kp = KeyPackage {
                owner_did: format!("did:key:{name}"),
            };
            manager.join_context(&handle, kp).await.unwrap();
        }

        assert_eq!(manager.member_count("test-ctx"), Some(4));
        assert!(manager.is_member("test-ctx", "did:key:alice"));
        assert!(manager.is_member("test-ctx", "did:key:bob"));
        assert!(manager.is_member("test-ctx", "did:key:charlie"));

        let mut dids = manager.member_dids("test-ctx");
        dids.sort();
        assert_eq!(
            dids,
            vec![
                "did:key:alice",
                "did:key:bob",
                "did:key:charlie",
                "did:key:creator"
            ]
        );
    }

    #[tokio::test]
    async fn member_role_assignment() {
        let (manager, handle) = setup_active_context().await;

        // Creator should be admin.
        let role = manager.member_role("test-ctx", "did:key:creator");
        assert!(role.is_some());
        assert_eq!(role.unwrap().role_name, "admin");

        // Add a member.
        let kp = KeyPackage {
            owner_did: "did:key:alice".into(),
        };
        manager.join_context(&handle, kp).await.unwrap();

        let role = manager.member_role("test-ctx", "did:key:alice");
        assert!(role.is_some());
        assert_eq!(role.unwrap().role_name, "member");
    }
}
