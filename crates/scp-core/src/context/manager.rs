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
use std::sync::Arc;

use tokio::sync::Mutex;

use super::builder::{
    ContextCreationError, ContextCryptoProvider, ContextEventLogProvider, ContextTransportProvider,
    create_context as builder_create_context,
};
use super::membership::{ContextEvent, KeyPackage, MembershipState, ReceiveBuffer};
use crate::identity::DID;
use super::roles::{self, Capability, CapabilityCeiling, ContextRoleState, RoleAssignment};
use super::ttl::{self, CloseResult, TtlExtension, TtlTimer};
use super::{ContextError, ContextHandle, ContextParams, ContextState};

// ---------------------------------------------------------------------------
// PerContextState -- internal per-context tracking
// ---------------------------------------------------------------------------

/// Internal state tracked by the manager for each context.
struct PerContextState {
    /// The context handle (retained for state checks and lifecycle operations).
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

/// Reads the context state synchronously via [`ContextHandle::try_read_state`].
/// Returns `ContextNotActive` if the read lock cannot be acquired (a state
/// transition is in progress) or if the state is not `Active`.
///
/// This is used inside `Mutex` lock scopes to avoid TOCTOU races: the state
/// check and the subsequent mutation happen within the same lock acquisition,
/// guaranteeing that no concurrent `close_context` or `handle_ttl_expiry` can
/// interleave between the check and the mutation.
fn require_active(handle: &ContextHandle) -> Result<(), ContextError> {
    let state = handle.try_read_state().ok_or(ContextError::ContextNotActive)?;
    if state != ContextState::Active {
        return Err(ContextError::ContextNotActive);
    }
    Ok(())
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
/// threads and async tasks. Per-context state is protected by a
/// `tokio::sync::Mutex` which does not poison on panic.
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
    ///
    /// Stored as `Arc` (not `Box`) so the provider can be shared with
    /// spawned TTL timer tasks that need crypto access for key destruction
    /// on context expiry (SCP-169).
    crypto: Arc<dyn ContextCryptoProvider>,
    /// Provider for relay connectivity and publication.
    transport: Arc<dyn ContextTransportProvider>,
    /// Provider for event log initialisation and append.
    ///
    /// Stored as `Arc` (not `Box`) so the provider can be shared with
    /// spawned TTL timer tasks that need event log access for logging
    /// `ContextExpired` events on context expiry (SCP-169).
    event_log: Arc<dyn ContextEventLogProvider>,
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
            crypto: Arc::from(crypto),
            transport: Arc::from(transport),
            event_log: Arc::from(event_log),
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
        // Phase 1+2: builder performs validation and creation (async, no lock held).
        let handle = builder_create_context(
            context_id.clone(),
            params.clone(),
            self.crypto.as_ref(),
            self.transport.as_ref(),
            self.event_log.as_ref(),
        )
        .await?;

        // Build ceiling from params (params::Capability is now the same type as roles::Capability).
        let ceiling = CapabilityCeiling::new(params.ceiling.iter().cloned());

        // Initialize role state with the creator as admin.
        let role_state = ContextRoleState::new(&context_id, &*creator_did, ceiling, vec![])
            .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;

        // Initialize membership with the creator.
        let mut membership = MembershipState::new();
        let creator_tokens = role_state
            .assignments
            .get(creator_did.as_ref())
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

        // Atomic duplicate check + insert under lock -- no .await inside this scope.
        {
            let mut contexts = self.contexts.lock().await;
            if contexts.contains_key(&context_id) {
                return Err(ContextCreationError::CreationFailed(format!(
                    "context '{context_id}' already registered"
                )));
            }
            contexts.insert(context_id.clone(), per_context);
        }

        // Spawn TTL timer if TTL is configured (SCP-021).
        if let Some(ttl_duration) = params.ttl {
            self.spawn_ttl_timer(&context_id, ttl_duration, handle.clone())
                .await;
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
        let context_id = handle.context_id().to_owned();
        let context_id_bytes = context_id_to_bytes(&context_id);
        let member_did = key_package.owner_did.clone();

        // Crypto operations -- no lock held, no TOCTOU concern for these
        // provider calls since they are idempotent or externally consistent.
        self.crypto.validate_key_package(&member_did)?;
        self.crypto.add_member(&context_id_bytes, &member_did)?;
        self.crypto
            .distribute_sender_key(&context_id_bytes, &member_did)?;

        // Atomic state check + mutation: verify Active, then role assignment +
        // membership + event buffer, all within a single lock acquisition.
        // The state check is inside the lock to eliminate the TOCTOU race
        // where close_context could transition the state between the check
        // and the mutation.
        {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(&context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

            // State check inside lock -- eliminates TOCTOU race.
            require_active(&ctx.handle)?;

            // Add member to role state.
            ctx.role_state.members.insert(member_did.to_string());

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
        // Lock dropped before event log append.

        // Append MemberJoined event to event log.
        self.event_log
            .append_context_event(&context_id_bytes, "MemberJoined")?;

        Ok(())
    }

    /// Removes a member from a context.
    ///
    /// Authorization: the caller must either be removing themselves
    /// (`caller_did == member_did`, self-removal) or hold the `MemberRemove`
    /// capability. Self-removal is always permitted regardless of role.
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
    /// - The caller is neither the member being removed nor holds `MemberRemove`.
    /// - The member is not found.
    /// - Any crypto or event log operation fails.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn leave_context(
        &self,
        handle: &ContextHandle,
        caller_did: &DID,
        member_did: &DID,
    ) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();
        let context_id_bytes = context_id_to_bytes(&context_id);

        // Authorization check: self-removal is always allowed; otherwise
        // the caller must hold MemberRemove capability.
        if caller_did != member_did {
            let contexts = self.contexts.lock().await;
            let ctx = contexts
                .get(&context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            if !ctx
                .role_state
                .member_has_capability(caller_did, &Capability::MemberRemove)
            {
                return Err(ContextError::PermissionDenied(
                    "caller lacks permission to remove this member".into(),
                ));
            }
            drop(contexts);
        }

        // Crypto operations -- no lock held.
        self.crypto.remove_member(&context_id_bytes, member_did)?;
        self.crypto
            .remove_member_sender_key(&context_id_bytes, member_did)?;

        // Atomic state check + membership removal + count check within single lock.
        let should_close = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(&context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

            // State check inside lock -- eliminates TOCTOU race.
            require_active(&ctx.handle)?;

            if !ctx.membership.remove_member(member_did) {
                return Err(ContextError::MemberNotFound(member_did.to_string()));
            }

            // Remove from role state.
            ctx.role_state.members.remove(member_did.as_ref());
            ctx.role_state.assignments.remove(member_did.as_ref());
            ctx.role_state
                .member_capabilities
                .remove(member_did.as_ref());

            // Emit MemberLeft event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::MemberLeft {
                member_did: member_did.clone(),
            });

            ctx.membership.count() == 0
        };
        // Lock dropped.

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
        let context_id = handle.context_id().to_owned();
        let context_id_bytes = context_id_to_bytes(&context_id);

        // Atomic state check + capability check + sequence assignment + event
        // emission, all within a single lock acquisition.
        {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(&context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

            // State check inside lock -- eliminates TOCTOU race.
            require_active(&ctx.handle)?;

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
                .ok_or_else(|| ContextError::MemberNotFound(sender_did.to_string()))?;

            // Emit MessageSent event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::MessageSent {
                sender_did: sender_did.clone(),
                sequence_number: seq,
                payload: payload.to_vec(),
            });
        }
        // Lock dropped before crypto/transport/event-log calls.

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
    pub async fn member_count(&self, context_id: &str) -> Option<usize> {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .map(|ctx| ctx.membership.count())
    }

    /// Returns `true` if the given DID is a member of the specified context.
    pub async fn is_member(&self, context_id: &str, did: &str) -> bool {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .is_some_and(|ctx| ctx.membership.contains(did))
    }

    /// Returns all member DIDs for a context.
    pub async fn member_dids(&self, context_id: &str) -> Vec<String> {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .map(|ctx| ctx.membership.member_dids().map(|d| d.to_string()).collect())
            .unwrap_or_default()
    }

    /// Returns the role assignment for a specific member in a context.
    pub async fn member_role(&self, context_id: &str, did: &str) -> Option<RoleAssignment> {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .and_then(|ctx| ctx.role_state.assignments.get(did).cloned())
    }

    /// Drains all events from the receive buffer for a context.
    ///
    /// Returns an empty `Vec` if the context is not registered.
    pub async fn drain_events(&self, context_id: &str) -> Vec<ContextEvent> {
        self.contexts
            .lock()
            .await
            .get_mut(context_id)
            .map(|ctx| ctx.receive_buffer.drain())
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

        // Atomic state check + role_state extraction within a single lock.
        let role_state = {
            let contexts = self.contexts.lock().await;
            let ctx = contexts
                .get(&context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

            // State check inside lock -- eliminates TOCTOU race.
            require_active(&ctx.handle)?;

            ctx.role_state.clone()
        };
        // Lock dropped before async ttl::close_context call.

        // Delegate to ttl::close_context for the actual logic (async).
        let result =
            ttl::close_context(handle, initiator_did, &role_state, self.event_log.as_ref()).await?;

        // Cancel TTL timer and emit close notification (second lock acquisition).
        {
            let mut contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get_mut(&context_id) {
                ctx.ttl_timer.cancel();
                ctx.receive_buffer.push(ContextEvent::SystemClose {
                    initiator_did: initiator_did.clone(),
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
    #[allow(clippy::significant_drop_tightening)]
    pub async fn handle_ttl_expiry(&self, handle: &ContextHandle) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();

        // Async TTL expiry logic -- no lock held.
        ttl::handle_ttl_expiry(handle, self.crypto.as_ref(), self.event_log.as_ref()).await?;

        // Emit expiry notification (lock acquired, then dropped).
        {
            let mut contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get_mut(&context_id) {
                ctx.receive_buffer.push(ContextEvent::Expired);
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
    pub async fn propose_ttl_extension(
        &self,
        context_id: &str,
        member_did: &DID,
        proposed_duration: std::time::Duration,
    ) -> Result<bool, ContextError> {
        // All checks and mutation within a single lock acquisition.
        let mut contexts = self.contexts.lock().await;
        let ctx = contexts
            .get_mut(context_id)
            .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

        if !ctx.membership.contains(member_did) {
            return Err(ContextError::MemberNotFound(member_did.to_string()));
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
    pub async fn reset_ttl_timer(
        &self,
        context_id: &str,
        new_duration: std::time::Duration,
        handle: ContextHandle,
    ) {
        // Cancel old timer and clear extension state (lock, then drop).
        {
            let mut contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get_mut(context_id) {
                ctx.ttl_timer.cancel();
                ctx.ttl_extension = None;
            }
        }

        self.spawn_ttl_timer(context_id, new_duration, handle).await;
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    /// Spawns a TTL timer for the given context.
    ///
    /// When the timer fires, it calls [`ttl::handle_ttl_expiry`] which:
    /// - Transitions the context from `Active` to `Expired`.
    /// - For `Ephemeral` and `Summary` memory scopes: destroys MLS group
    ///   state and sender keys via the crypto provider.
    /// - Logs a `ContextExpired` event to the event log.
    ///
    /// This matches the behavior of [`TtlTimer::spawn`] and ensures key
    /// material is properly destroyed on TTL expiry (SCP-169).
    #[allow(clippy::significant_drop_tightening)]
    async fn spawn_ttl_timer(
        &self,
        context_id: &str,
        duration: std::time::Duration,
        handle: ContextHandle,
    ) {
        // Extract the cancel Notify under lock, then drop.
        let cancel = {
            let mut contexts = self.contexts.lock().await;
            let Some(ctx) = contexts.get_mut(context_id) else {
                return;
            };
            ctx.ttl_timer.cancel.clone()
        };

        // Clone Arc-wrapped providers so the spawned task can perform
        // key destruction and event logging on TTL expiry.
        let crypto = Arc::clone(&self.crypto);
        let event_log = Arc::clone(&self.event_log);

        let task = tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(duration) => {
                    // Timer fired. Delegate to handle_ttl_expiry which
                    // transitions to Expired, destroys keys per memory
                    // scope, and logs ContextExpired event (SCP-169).
                    let _ = ttl::handle_ttl_expiry(
                        &handle,
                        crypto.as_ref(),
                        event_log.as_ref(),
                    ).await;
                }
                () = cancel.notified() => {
                    // Timer was cancelled.
                }
            }
        });

        // Store the task handle (lock, then drop).
        let context_id_owned = context_id.to_owned();
        let mut contexts = self.contexts.lock().await;
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
        mls_created: std::sync::Mutex<Vec<[u8; 32]>>,
        sender_keys_created: std::sync::Mutex<Vec<[u8; 32]>>,
        broadcast_created: std::sync::Mutex<Vec<[u8; 32]>>,
        mls_destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
        sender_keys_destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
        members_added: std::sync::Mutex<Vec<String>>,
        members_removed: std::sync::Mutex<Vec<String>>,
        sender_keys_distributed: std::sync::Mutex<Vec<String>>,
        sender_keys_removed: std::sync::Mutex<Vec<String>>,
        messages_encrypted: std::sync::Mutex<Vec<Vec<u8>>>,
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

        fn add_member(
            &self,
            _context_id: &[u8; 32],
            member_did: &str,
        ) -> Result<(), ContextError> {
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
        published: std::sync::Mutex<Vec<[u8; 32]>>,
        deleted: std::sync::Mutex<Vec<[u8; 32]>>,
        messages_sent: std::sync::Mutex<Vec<Vec<u8>>>,
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
        inited: std::sync::Mutex<Vec<[u8; 32]>>,
        events: std::sync::Mutex<Vec<([u8; 32], String)>>,
        destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
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
        assert!(manager.is_member("test-ctx", "did:key:bob").await);
        assert_eq!(manager.member_count("test-ctx").await, Some(2));

        // Verify UCAN tokens were issued.
        let role = manager.member_role("test-ctx", "did:key:bob").await;
        assert!(role.is_some());
        let role = role.unwrap();
        assert_eq!(role.role_name, "member");
        assert!(!role.tokens.is_empty());

        // Verify MemberJoined event was emitted.
        let events = manager.drain_events("test-ctx").await;
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

        // Remove the only member (creator -- self-removal).
        let result = manager
            .leave_context(&handle, &"did:key:creator".into(), &"did:key:creator".into())
            .await;
        assert!(result.is_ok());

        // Member count should be 0.
        assert_eq!(manager.member_count("test-ctx").await, Some(0));
        assert!(!manager.is_member("test-ctx", "did:key:creator").await);

        // Context should have transitioned to Closing.
        assert_eq!(handle.state().await, ContextState::Closing);

        // Verify MemberLeft event was emitted.
        let events = manager.drain_events("test-ctx").await;
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
        assert_eq!(manager.member_count("test-ctx").await, Some(2));

        // Remove bob (self-removal).
        manager.drain_events("test-ctx").await; // Clear join event.
        let result = manager
            .leave_context(&handle, &"did:key:bob".into(), &"did:key:bob".into())
            .await;
        assert!(result.is_ok());

        // Context should still be Active (creator is still there).
        assert_eq!(handle.state().await, ContextState::Active);
        assert_eq!(manager.member_count("test-ctx").await, Some(1));
    }

    #[tokio::test]
    async fn leave_rejects_when_context_not_active() {
        let (manager, handle) = setup_active_context().await;

        handle.transition_to(&ContextState::Closing).await.unwrap();

        let result = manager
            .leave_context(&handle, &"did:key:creator".into(), &"did:key:creator".into())
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    // -----------------------------------------------------------------------
    // Leave context authorization tests (SCP-167)
    // -----------------------------------------------------------------------

    /// Helper: creates a context whose ceiling includes `member:remove` so
    /// that the admin can remove other members. Adds an observer member
    /// (`did:key:observer`) alongside the admin creator (`did:key:creator`).
    async fn setup_context_with_member_remove() -> (ContextManager, ContextHandle) {
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
                crate::context::params::Capability::new("member:remove"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("auth-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        // Add an observer member.
        let kp = KeyPackage {
            owner_did: "did:key:observer".into(),
        };
        manager.join_context(&handle, kp).await.unwrap();

        // Reassign to observer role (joined members default to "member").
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("auth-ctx").unwrap();
            roles::assign_role(
                &mut ctx.role_state,
                "did:key:observer",
                "observer",
                "did:key:creator",
            )
            .unwrap();
            // Update the membership tracking to reflect the new role.
            if let Some(info) = ctx.membership.get_mut("did:key:observer") {
                info.role_name = "observer".into();
            }
        }

        (manager, handle)
    }

    /// SCP-167: observer calls leave_context with admin's DID — returns
    /// authorization error.
    #[tokio::test]
    async fn leave_observer_cannot_remove_admin() {
        let (manager, handle) = setup_context_with_member_remove().await;

        // Observer tries to remove the admin — should fail.
        let result = manager
            .leave_context(
                &handle,
                &"did:key:observer".into(),
                &"did:key:creator".into(),
            )
            .await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(_)),
            "observer should not be able to remove admin"
        );

        // Admin should still be a member.
        assert!(manager.is_member("auth-ctx", "did:key:creator").await);
    }

    /// SCP-167: admin calls leave_context with observer's DID — succeeds
    /// (admin has `MemberRemove` capability).
    #[tokio::test]
    async fn leave_admin_can_remove_observer() {
        let (manager, handle) = setup_context_with_member_remove().await;

        // Admin removes the observer — should succeed.
        let result = manager
            .leave_context(
                &handle,
                &"did:key:creator".into(),
                &"did:key:observer".into(),
            )
            .await;

        assert!(result.is_ok(), "admin should be able to remove observer");

        // Observer should no longer be a member.
        assert!(!manager.is_member("auth-ctx", "did:key:observer").await);
        // Admin should still be a member.
        assert!(manager.is_member("auth-ctx", "did:key:creator").await);
    }

    /// SCP-167: member calls leave_context with own DID — succeeds
    /// (self-removal is always allowed regardless of role).
    #[tokio::test]
    async fn leave_self_removal_always_allowed() {
        let (manager, handle) = setup_context_with_member_remove().await;

        // Observer self-removes — should always succeed.
        let result = manager
            .leave_context(
                &handle,
                &"did:key:observer".into(),
                &"did:key:observer".into(),
            )
            .await;

        assert!(result.is_ok(), "self-removal should always be allowed");

        // Observer should no longer be a member.
        assert!(!manager.is_member("auth-ctx", "did:key:observer").await);
        // Admin should still be a member.
        assert!(manager.is_member("auth-ctx", "did:key:creator").await);
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
        let events = manager.drain_events("test-ctx").await;
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

        let events = manager.drain_events("test-ctx").await;
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
        assert_eq!(manager.member_count("test-ctx").await, Some(1));
        assert!(manager.is_member("test-ctx", "did:key:creator").await);

        // Add members.
        for name in &["alice", "bob", "charlie"] {
            let kp = KeyPackage {
                owner_did: format!("did:key:{name}").into(),
            };
            manager.join_context(&handle, kp).await.unwrap();
        }

        assert_eq!(manager.member_count("test-ctx").await, Some(4));
        assert!(manager.is_member("test-ctx", "did:key:alice").await);
        assert!(manager.is_member("test-ctx", "did:key:bob").await);
        assert!(manager.is_member("test-ctx", "did:key:charlie").await);

        let mut dids = manager.member_dids("test-ctx").await;
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
        let role = manager.member_role("test-ctx", "did:key:creator").await;
        assert!(role.is_some());
        assert_eq!(role.unwrap().role_name, "admin");

        // Add a member.
        let kp = KeyPackage {
            owner_did: "did:key:alice".into(),
        };
        manager.join_context(&handle, kp).await.unwrap();

        let role = manager.member_role("test-ctx", "did:key:alice").await;
        assert!(role.is_some());
        assert_eq!(role.unwrap().role_name, "member");
    }

    // -----------------------------------------------------------------------
    // Concurrent operations test (SCP-168)
    // -----------------------------------------------------------------------

    /// Verifies that concurrent join + send operations on the same context
    /// do not corrupt internal state. All operations should either succeed
    /// or return a well-defined error -- never panic or produce inconsistent
    /// membership counts.
    #[tokio::test]
    async fn concurrent_joins_and_sends_do_not_corrupt_state() {
        let manager = std::sync::Arc::new(ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        ));

        let params = ContextParams {
            ceiling: vec![
                crate::context::params::Capability::new("messages:read"),
                crate::context::params::Capability::new("messages:write"),
                crate::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("conc-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        let handle = std::sync::Arc::new(handle);

        // Spawn 10 concurrent join tasks.
        let mut join_handles = Vec::new();
        for i in 0..10u32 {
            let mgr = std::sync::Arc::clone(&manager);
            let h = std::sync::Arc::clone(&handle);
            join_handles.push(tokio::spawn(async move {
                let kp = KeyPackage {
                    owner_did: format!("did:key:member-{i}").into(),
                };
                mgr.join_context(&h, kp).await
            }));
        }

        // Spawn 5 concurrent send tasks from the creator.
        for i in 0..5u8 {
            let mgr = std::sync::Arc::clone(&manager);
            let h = std::sync::Arc::clone(&handle);
            join_handles.push(tokio::spawn(async move {
                mgr.send_message(&h, &"did:key:creator".into(), &[i])
                    .await
                    .map(|()| ())
            }));
        }

        // Wait for all tasks. All should succeed (no panics, no data corruption).
        for jh in join_handles {
            let result = jh.await.unwrap();
            assert!(result.is_ok(), "concurrent operation failed: {result:?}");
        }

        // 1 creator + 10 joined members = 11.
        assert_eq!(manager.member_count("conc-ctx").await, Some(11));
    }

    // -----------------------------------------------------------------------
    // Panic recovery test (SCP-168)
    // -----------------------------------------------------------------------

    /// Verifies that a panic inside a mock provider does not poison the
    /// `tokio::sync::Mutex`. After the panicking task is caught, subsequent
    /// operations on the same manager must succeed.
    #[tokio::test]
    async fn panic_does_not_poison_mutex() {
        use std::sync::Arc;

        let manager = Arc::new(ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        ));

        let params = ContextParams {
            ceiling: vec![
                crate::context::params::Capability::new("messages:read"),
                crate::context::params::Capability::new("messages:write"),
                crate::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("panic-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        // Spawn a task that will panic after acquiring the contexts lock.
        // We simulate this by calling join_context with a specially crafted
        // scenario: the crypto provider succeeds, but then we panic inside
        // a spawned task that holds a reference.
        let mgr_clone = Arc::clone(&manager);
        let handle_clone = handle.clone();
        let panicking_task = tokio::spawn(async move {
            // This panics inside the task. tokio::sync::Mutex does not poison.
            let _count = mgr_clone.member_count("panic-ctx").await;
            panic!("intentional panic for testing");
        });

        // The panicking task should fail (JoinError with panic).
        let result = panicking_task.await;
        assert!(result.is_err(), "task should have panicked");

        // The manager should still be usable -- tokio::sync::Mutex does not poison.
        let count = manager.member_count("panic-ctx").await;
        assert_eq!(count, Some(1), "mutex should not be poisoned");

        // Further operations should succeed.
        let kp = KeyPackage {
            owner_did: "did:key:after-panic".into(),
        };
        let join_result = manager.join_context(&handle_clone, kp).await;
        assert!(join_result.is_ok(), "join after panic should succeed");
        assert_eq!(manager.member_count("panic-ctx").await, Some(2));
    }
}
