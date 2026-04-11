//! Simple queries and local DID management.

use super::{
    Arc, Capability, CommitFaultMarker, ContextError, ContextEvent, ContextEventLogProvider,
    ContextManager, ContextParams, ContextRoleState, DID, PendingCommit, RoleAssignment, Zeroizing,
    instrument,
};

#[allow(clippy::significant_drop_tightening)]
impl ContextManager {
    /// Registers a DID as controlled by the local node/SDK.
    ///
    /// The node layer calls this at startup (and when new DIDs are created)
    /// to inform the `ContextManager` which DIDs are locally controlled.
    /// This enables defense-in-depth validation in
    /// [`handle_broadcast_key_request`](Self::handle_broadcast_key_request),
    /// which verifies the `author_did` is locally controlled before
    /// processing the key request.
    ///
    /// Registering the same DID multiple times is idempotent.
    #[instrument(skip_all)]
    pub async fn register_local_did(&self, did: DID) {
        self.local_dids.write().await.insert(did);
    }

    /// Sets the payment adapter for the 9-step paid action flow (spec §19.2.2).
    ///
    /// When set, `authorize_paid_action`→`complete_paid_action` runs the
    /// full escrow sequence for each paid entry point (`send_message`,
    /// `join_context`, `invoke_tool`). When `None`, those entry points
    /// still enforce budget tracking but skip the payment rail integration.
    ///
    /// Can be called at any time; takes effect for subsequent actions.
    pub fn set_payment_adapter(
        &mut self,
        adapter: Arc<dyn crate::economy::adapter::PaymentAdapterDyn>,
    ) {
        self.payment_adapter = Some(adapter);
    }

    /// Returns `true` if the given DID is registered as locally controlled.
    ///
    /// This is a read-only query useful for diagnostics and testing.
    #[instrument(skip_all)]
    pub async fn is_local_did(&self, did: &DID) -> bool {
        self.local_dids.read().await.contains(did)
    }

    /// Returns the broadcast key and epoch for a locally controlled author
    /// in a broadcast context.
    ///
    /// This enables FFI bridges to auto-resolve broadcast keys for
    /// `enable_site_projection` without requiring the caller to manually
    /// provide the key. The key is returned as `Zeroizing<[u8; 32]>` to
    /// ensure sensitive material is wiped on drop.
    ///
    /// # Security
    ///
    /// Only returns keys for DIDs in [`local_dids`](Self::register_local_did).
    /// This prevents leaking broadcast keys for remote authors.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered
    ///   or is not a broadcast context.
    /// - [`ContextError::PermissionDenied`] if `author_did` is not locally
    ///   controlled.
    /// - [`ContextError::MemberNotFound`] if `author_did` is not a registered
    ///   author in the broadcast context.
    #[instrument(skip_all, fields(context_id))]
    pub async fn get_broadcast_key_for_local_author(
        &self,
        context_id: &str,
        author_did: &str,
    ) -> Result<(Zeroizing<[u8; 32]>, u64), ContextError> {
        // Verify the DID is locally controlled.
        if !self.local_dids.read().await.contains(author_did) {
            return Err(ContextError::PermissionDenied(format!(
                "author DID is not controlled by the local node: {author_did}"
            )));
        }

        let contexts = self.contexts.lock().await;
        let ctx = contexts
            .get(context_id)
            .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;

        let bc = ctx
            .broadcast_context
            .as_ref()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        let author = bc.get_author(author_did).ok_or_else(|| {
            ContextError::MemberNotFound(format!("author not found: {author_did}"))
        })?;

        let key_bytes = Zeroizing::new(*author.broadcast_key.as_bytes());
        Ok((key_bytes, author.epoch))
    }

    /// Returns the current member count for a context.
    ///
    /// Returns `None` if the context is not registered with this manager.
    #[instrument(skip_all, fields(context_id))]
    pub async fn member_count(&self, context_id: &str) -> Option<usize> {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .map(|ctx| ctx.membership.count())
    }

    /// Returns `true` if the given DID is a member of the specified context.
    #[instrument(skip_all, fields(context_id))]
    pub async fn is_member(&self, context_id: &str, did: &str) -> bool {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .is_some_and(|ctx| ctx.membership.contains(did))
    }

    /// Returns all member DIDs for a context.
    #[instrument(skip_all, fields(context_id))]
    pub async fn member_dids(&self, context_id: &str) -> Vec<String> {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .map(|ctx| {
                ctx.membership
                    .member_dids()
                    .map(std::string::ToString::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns the role assignment for a specific member in a context.
    #[instrument(skip_all, fields(context_id))]
    pub async fn member_role(&self, context_id: &str, did: &str) -> Option<RoleAssignment> {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .and_then(|ctx| ctx.role_state.assignments.get(did).cloned())
    }

    /// Returns a clone of the context's creation parameters, or `None` if the
    /// context is not registered with this manager.
    ///
    /// Used by FFI bridges to read context-configured limits (e.g.
    /// `session_cap`, `max_chain_depth`, `max_nesting_depth`) instead of
    /// hardcoding protocol defaults.
    #[instrument(skip_all, fields(context_id))]
    pub async fn context_params(&self, context_id: &str) -> Option<ContextParams> {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .map(|ctx| ctx.handle.params().clone())
    }

    /// Returns a clone of the role state for a context, or `None` if the
    /// context is not registered.
    ///
    /// Used by FFI bridges to re-sync their local role state copy after
    /// governance actions that modify roles/capabilities.
    #[instrument(skip_all, fields(context_id))]
    pub async fn get_role_state(&self, context_id: &str) -> Option<ContextRoleState> {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .map(|ctx| ctx.role_state.clone())
    }

    /// Drains all events from the receive buffer for a context.
    ///
    /// Returns an empty `Vec` if the context is not registered.
    #[instrument(skip_all, fields(context_id))]
    pub async fn drain_events(&self, context_id: &str) -> Vec<ContextEvent> {
        self.contexts
            .lock()
            .await
            .get_mut(context_id)
            .map(|ctx| ctx.receive_buffer.drain())
            .unwrap_or_default()
    }

    /// Returns the Merkle event log entries for a context.
    ///
    /// Delegates to `self.event_log.event_log_entries()`. Returns `Ok(None)`
    /// if no log exists for the context.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the event log provider fails.
    pub fn event_log_entries(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Option<Vec<crate::context::providers::event_log::EventLogEntry>>, ContextError>
    {
        self.event_log.event_log_entries(context_id)
    }

    /// Returns the event log provider for direct Merkle tree access.
    ///
    /// Primarily intended for the FFI layer to query event counts and
    /// Merkle roots without duplicating event log state.
    pub fn event_log_provider(&self) -> &dyn ContextEventLogProvider {
        self.event_log.as_ref()
    }

    /// Reports that a received envelope triggered degraded mode (§13.6) for a
    /// context.
    ///
    /// Called by the SDK/FFI layer after processing a received envelope whose
    /// `VersionCompatibility` is `DegradedMode`. This pushes a
    /// [`ContextEvent::DegradedMode`] to the context's receive buffer so the
    /// application layer can observe the degraded state via [`drain_events`].
    ///
    /// If `compat` is `VersionCompatibility::Exact`, this is a no-op (no
    /// event is emitted). If the context is not registered, this is also a
    /// no-op.
    ///
    /// NOTE: No production callers yet. Each FFI bridge's envelope receive path
    /// must call this after `check_version_compatibility` returns `DegradedMode`.
    /// Tracked by issue #1077 (FFI exposure of version-compatibility helpers).
    ///
    /// # Arguments
    ///
    /// * `context_id` — The context where the envelope was received.
    /// * `compat` — The version compatibility result from envelope processing.
    /// * `unsupported_features` — Human-readable descriptions of features
    ///   present in the remote version that the local implementation does not
    ///   support. At SCP/1.x there are no known feature flags; pass an empty
    ///   `Vec`.
    ///
    /// [`VersionCompatibility`]: scp_protocol::envelope::VersionCompatibility
    /// [`DegradedMode`]: scp_protocol::envelope::VersionCompatibility::DegradedMode
    /// [`drain_events`]: Self::drain_events
    #[instrument(skip_all, fields(context_id))]
    pub async fn report_degraded_mode(
        &self,
        context_id: &str,
        compat: scp_protocol::envelope::VersionCompatibility,
        unsupported_features: Vec<String>,
    ) {
        if let scp_protocol::envelope::VersionCompatibility::DegradedMode {
            local_minor,
            remote_minor,
        } = compat
        {
            let local_major =
                scp_protocol::envelope::version_major(scp_protocol::envelope::SCP_PROTOCOL_VERSION);
            let remote_major = local_major; // same major guaranteed by VersionCompatibility
            if let Some(ctx) = self.contexts.lock().await.get_mut(context_id) {
                ctx.receive_buffer.push(ContextEvent::DegradedMode {
                    context_id: context_id.to_owned(),
                    local_version: (local_major, local_minor),
                    remote_version: (remote_major, remote_minor),
                    unsupported_features,
                });
            }
        }
    }

    /// Generates and stores a per-member access key for explicit lifecycle
    /// management.
    ///
    /// Creates a fresh random 32-byte AES-256 access key at epoch 0 and
    /// stores it in the context's access key store. This is the explicit
    /// counterpart to the implicit key generation that happens during
    /// `AddMember` governance action execution (§9.17.2 step 1).
    ///
    /// If an access key already exists for this member, it is overwritten.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not
    ///   registered with this manager.
    /// - [`ContextError::MemberNotFound`] if `member_did` is not a member
    ///   of the context.
    #[instrument(skip_all, fields(context_id, member_did, caller_did))]
    pub async fn generate_context_access_key(
        &self,
        context_id: &str,
        member_did: &str,
        caller_did: &str,
    ) -> Result<(), ContextError> {
        let mut contexts = self.contexts.lock().await;
        let ctx = contexts
            .get_mut(context_id)
            .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;

        // Authorization: access key management requires admin (ContextClose).
        if !ctx
            .role_state
            .member_has_capability(caller_did, &Capability::ContextClose)
        {
            return Err(ContextError::PermissionDenied(
                "access key management requires admin capability".into(),
            ));
        }

        if !ctx.membership.contains(member_did) {
            return Err(ContextError::MemberNotFound(format!(
                "member not found: {member_did}"
            )));
        }

        let key = scp_protocol::crypto::access_keys::generate_access_key(context_id, member_did);
        ctx.access.access_key_store.set(context_id, member_did, key);
        Ok(())
    }

    /// Revokes (removes) a member's access key from the context's access
    /// key store.
    ///
    /// After revocation the member can no longer decrypt content encrypted
    /// with future CEKs. Historical content remains accessible until the
    /// member's local key material is destroyed.
    ///
    /// This is the explicit counterpart to the implicit key removal that
    /// happens during `Revoke` governance action execution
    /// (§9.17.2 step 3, ADR-038).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not
    ///   registered with this manager.
    /// - [`ContextError::MemberNotFound`] if no access key exists for
    ///   `member_did` in the context.
    #[instrument(skip_all, fields(context_id, member_did, caller_did))]
    pub async fn revoke_context_access_key(
        &self,
        context_id: &str,
        member_did: &str,
        caller_did: &str,
    ) -> Result<(), ContextError> {
        let mut contexts = self.contexts.lock().await;
        let ctx = contexts
            .get_mut(context_id)
            .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;

        // Authorization: access key management requires admin (ContextClose).
        if !ctx
            .role_state
            .member_has_capability(caller_did, &Capability::ContextClose)
        {
            return Err(ContextError::PermissionDenied(
                "access key management requires admin capability".into(),
            ));
        }

        ctx.access
            .access_key_store
            .remove(context_id, member_did)
            .ok_or_else(|| {
                ContextError::MemberNotFound(format!(
                    "no access key found for member: {member_did}"
                ))
            })?;
        Ok(())
    }

    /// Restores a member's access key by generating a new key at epoch 0.
    ///
    /// The restored member can decrypt future content only. Historical
    /// content encrypted during the revocation period remains permanently
    /// inaccessible because the old access key was destroyed and is never
    /// re-distributed (forward-only restoration, §9.16.8, ADR-038).
    ///
    /// This is the explicit counterpart to the implicit key restoration
    /// that happens during `RestoreAccess` governance action execution
    /// (§9.17.2 step 5).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not
    ///   registered with this manager.
    /// - [`ContextError::MemberNotFound`] if `member_did` is not a member
    ///   of the context.
    #[instrument(skip_all, fields(context_id, member_did, caller_did))]
    pub async fn restore_context_access_key(
        &self,
        context_id: &str,
        member_did: &str,
        caller_did: &str,
    ) -> Result<(), ContextError> {
        let mut contexts = self.contexts.lock().await;
        let ctx = contexts
            .get_mut(context_id)
            .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;

        // Authorization: access key management requires admin (ContextClose).
        if !ctx
            .role_state
            .member_has_capability(caller_did, &Capability::ContextClose)
        {
            return Err(ContextError::PermissionDenied(
                "access key management requires admin capability".into(),
            ));
        }

        if !ctx.membership.contains(member_did) {
            return Err(ContextError::MemberNotFound(format!(
                "member not found: {member_did}"
            )));
        }

        let key = scp_protocol::crypto::access_keys::generate_access_key(context_id, member_did);
        ctx.access.access_key_store.set(context_id, member_did, key);
        Ok(())
    }

    /// Stores an access key in a context's access key store.
    ///
    /// Called by the FFI layer after generating a new access key for a member.
    /// Overwrites any existing key for the same `(context_id, member_did)` pair.
    ///
    /// If the context is not registered, this is a no-op.
    #[instrument(skip_all, fields(context_id, member_did))]
    pub async fn set_access_key(
        &self,
        context_id: &str,
        member_did: &str,
        key: scp_protocol::crypto::access_keys::AccessKey,
    ) {
        if let Some(ctx) = self.contexts.lock().await.get_mut(context_id) {
            ctx.access.access_key_store.set(context_id, member_did, key);
        }
    }

    /// Removes a member's access key from a context's access key store.
    ///
    /// Called by the FFI layer on access key revocation. If no key exists
    /// for the pair, or the context is not registered, this is a no-op.
    #[instrument(skip_all, fields(context_id, member_did))]
    pub async fn remove_access_key(&self, context_id: &str, member_did: &str) {
        if let Some(ctx) = self.contexts.lock().await.get_mut(context_id) {
            ctx.access.access_key_store.remove(context_id, member_did);
        }
    }

    /// Injects an access key into a context's access key store.
    ///
    /// Test-only method for setting up access keys without going through
    /// the full key distribution protocol. Production code MUST use the
    /// proper key generation + distribution path.
    #[cfg(feature = "testing")]
    pub async fn inject_access_key(
        &self,
        context_id: &str,
        member_did: &str,
        key: scp_protocol::crypto::access_keys::AccessKey,
    ) {
        if let Some(ctx) = self.contexts.lock().await.get_mut(context_id) {
            ctx.access.access_key_store.set(context_id, member_did, key);
        }
    }

    /// Retrieves a clone of the access key for a member in a context.
    ///
    /// Test-only method for extracting access keys from the manager's
    /// internal store.
    #[cfg(feature = "testing")]
    pub async fn get_access_key(
        &self,
        context_id: &str,
        member_did: &str,
    ) -> Option<scp_protocol::crypto::access_keys::AccessKey> {
        let contexts = self.contexts.lock().await;
        contexts
            .get(context_id)?
            .access
            .access_key_store
            .get(context_id, member_did)
            .cloned()
    }

    /// Retrieves clones of ALL access keys for a context.
    ///
    /// Test-only method for extracting all access keys from the manager's
    /// internal store. Returns a map of `member_did -> AccessKey`.
    #[cfg(feature = "testing")]
    pub async fn get_all_access_keys(
        &self,
        context_id: &str,
    ) -> std::collections::HashMap<String, scp_protocol::crypto::access_keys::AccessKey> {
        let contexts = self.contexts.lock().await;
        contexts
            .get(context_id)
            .map(|ctx| ctx.access.access_key_store.get_all(context_id))
            .unwrap_or_default()
    }

    /// Returns a clone of the persistent MLS Commit retry queue for a context
    /// (PR #1606 C6).
    ///
    /// Each entry represents an MLS Commit (`RemoveMember`,
    /// `RotateContentKeys`, `ResetMember`, or `LeaveContext`) whose
    /// `transport.send_message` call previously failed and which is being
    /// retried by the governance timeout task with exponential backoff.
    /// SDK consumers SHOULD surface non-empty queues to the application
    /// layer because the local state mutation has happened but at least one
    /// remote member has not yet seen the commit.
    ///
    /// Returns an empty `Vec` if the context is not registered or has no
    /// pending commits.
    #[instrument(skip_all, fields(context_id))]
    pub async fn pending_commits(&self, context_id: &str) -> Vec<PendingCommit> {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .map(|ctx| ctx.pending_commits.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns the active commit fault marker for a context, if any (PR #1606 C6).
    ///
    /// `Some(marker)` indicates that a previous MLS Commit broadcast exhausted
    /// its retry budget and the context is in fail-close state — subsequent
    /// `execute_governance_action` and `leave_context` calls return
    /// [`ContextError::CommitBroadcastFault`] until the marker is cleared via
    /// [`acknowledge_commit_fault`](Self::acknowledge_commit_fault).
    ///
    /// Returns `None` if the context is not registered or has no fault marker.
    #[instrument(skip_all, fields(context_id))]
    pub async fn commit_fault(&self, context_id: &str) -> Option<CommitFaultMarker> {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .and_then(|ctx| ctx.commit_fault.clone())
    }
}
