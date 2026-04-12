//! Simple queries and local DID management.

use super::{
    Arc, Capability, CommitFaultMarker, ContextError, ContextEvent, ContextEventLogProvider,
    ContextManager, ContextParams, ContextRoleState, DID, PendingCommit, RoleAssignment, Zeroizing,
    instrument,
};

/// Maximum number of checkpoints retained per context. Older checkpoints
/// are drained when this limit is exceeded to prevent unbounded growth.
const MAX_RETAINED_CHECKPOINTS: usize = 100;

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

    /// Grants budget to a member in a context.
    ///
    /// Test-only method for seeding `MemberBudgetTracker` grants
    /// without going through the full `ApproveSpend` governance
    /// proposal pipeline. Used by integration tests to verify the
    /// runtime's `invoke_tool_with_economy` deducts budget correctly
    /// (PR #1606 / C4 — bridge tool-invoke economy wiring). Production
    /// code MUST use the `ApproveSpend` governance action.
    #[cfg(feature = "testing")]
    pub async fn grant_budget_for_test(
        &self,
        context_id: &str,
        member_did: &scp_identity::DID,
        amount: scp_protocol::economy::types::Amount,
    ) {
        if let Some(ctx) = self.contexts.lock().await.get_mut(context_id) {
            ctx.governance.budget_tracker.grant(member_did, amount);
        }
    }

    /// Returns the remaining budget for a member in a context.
    ///
    /// Test-only accessor for asserting the post-call state of the
    /// per-DID budget after `invoke_tool_with_economy` runs. Returns
    /// zero if the context is unknown.
    #[cfg(feature = "testing")]
    pub async fn remaining_budget_for_test(
        &self,
        context_id: &str,
        member_did: &scp_identity::DID,
    ) -> scp_protocol::economy::types::Amount {
        let contexts = self.contexts.lock().await;
        contexts
            .get(context_id)
            .map_or(scp_protocol::economy::types::Amount::new(0), |ctx| {
                ctx.governance.budget_tracker.remaining(member_did)
            })
    }

    /// Returns the per-DID velocity (number of recent paid actions) for
    /// a member in a context within the velocity window.
    ///
    /// Test-only accessor for verifying that
    /// `invoke_tool_with_economy` records the invocation in the
    /// per-DID velocity tracker. The bridges' previous bypass path
    /// did not record velocity at all, so the assertion in PR #1606
    /// C4 needs this hook to fail loudly on regression.
    #[cfg(feature = "testing")]
    pub async fn velocity_for_test(
        &self,
        context_id: &str,
        member_did: &scp_identity::DID,
        now_secs: u64,
    ) -> u64 {
        let contexts = self.contexts.lock().await;
        contexts.get(context_id).map_or(0, |ctx| {
            ctx.governance
                .velocity_tracker
                .get_velocity(member_did, now_secs)
        })
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

    // -------------------------------------------------------------------------
    // Checkpoint operations (§9.9.3, ADR-011 AC-8)
    // -------------------------------------------------------------------------

    /// Creates a consistency checkpoint if one is due based on event count
    /// or time interval thresholds.
    ///
    /// A checkpoint is due when either:
    /// - 50 events have been appended since the last checkpoint, or
    /// - 10 minutes have elapsed since the last checkpoint.
    ///
    /// The checkpoint captures the Merkle root, event count, and MLS epoch at
    /// the current point in time, then signs a canonical hash over those fields
    /// using Ed25519. The signature commits to a domain-separated canonical
    /// hash (see [`scp_event_log::checkpoint::compute_checkpoint_canonical_hash`]).
    ///
    /// Returns `Ok(Some(checkpoint))` if one was created, `Ok(None)` if not yet due.
    ///
    /// Called from `finalize_send` and `deliver_message_and_drain_buffered` after
    /// each event log append.
    pub(super) fn create_checkpoint_if_due(
        &self,
        context_id: &str,
        ctx: &mut super::PerContextState,
        sender_did: &DID,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Option<scp_event_log::checkpoint::ConsistencyCheckpoint> {
        let now = self.clock.now_secs();
        let events_due = ctx.checkpoint_events_since >= 50;
        // Time-based checkpoints require at least one event — creating a
        // checkpoint for zero events is wasteful and indistinguishable from
        // the previous checkpoint.
        let time_due = ctx.checkpoint_events_since > 0
            && now.saturating_sub(ctx.checkpoint_last_time_secs) >= 600;

        if !events_due && !time_due {
            return None;
        }

        let cp = Self::build_checkpoint(
            context_id,
            ctx,
            sender_did,
            signing_key,
            now,
            &*self.event_log,
        );

        ctx.checkpoint_events_since = 0;
        ctx.checkpoint_last_time_secs = now;
        ctx.checkpoints.push(cp.clone());

        if ctx.checkpoints.len() > MAX_RETAINED_CHECKPOINTS {
            ctx.checkpoints
                .drain(..ctx.checkpoints.len() - MAX_RETAINED_CHECKPOINTS);
        }

        tracing::debug!(
            context_id,
            event_count = cp.event_count,
            "consistency checkpoint created (§9.9.3)"
        );

        Some(cp)
    }

    /// Unconditionally creates a consistency checkpoint regardless of whether
    /// the event/time thresholds have been reached.
    ///
    /// Used by `close_context` to ensure a final checkpoint is always
    /// generated before context archival (§9.9.3).
    pub(super) fn force_create_checkpoint(
        &self,
        context_id: &str,
        ctx: &mut super::PerContextState,
        sender_did: &DID,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> scp_event_log::checkpoint::ConsistencyCheckpoint {
        let now = self.clock.now_secs();
        let cp = Self::build_checkpoint(
            context_id,
            ctx,
            sender_did,
            signing_key,
            now,
            &*self.event_log,
        );

        ctx.checkpoint_events_since = 0;
        ctx.checkpoint_last_time_secs = now;
        ctx.checkpoints.push(cp.clone());

        if ctx.checkpoints.len() > MAX_RETAINED_CHECKPOINTS {
            ctx.checkpoints
                .drain(..ctx.checkpoints.len() - MAX_RETAINED_CHECKPOINTS);
        }

        tracing::info!(
            context_id,
            event_count = cp.event_count,
            "forced final checkpoint on context close (§9.9.3)"
        );

        cp
    }

    /// Builds a signed checkpoint from the current event log and context state.
    fn build_checkpoint(
        context_id: &str,
        ctx: &super::PerContextState,
        sender_did: &DID,
        signing_key: &ed25519_dalek::SigningKey,
        now: u64,
        event_log: &dyn super::ContextEventLogProvider,
    ) -> scp_event_log::checkpoint::ConsistencyCheckpoint {
        let context_id_bytes = super::context_id_to_bytes(context_id);
        let merkle_root = event_log
            .event_log_merkle_root(&context_id_bytes)
            .unwrap_or([0u8; 32]);
        let event_count = event_log
            .event_log_entries(&context_id_bytes)
            .ok()
            .flatten()
            .map_or(0, |entries| entries.len() as u64);

        // Encrypted contexts (no broadcast_context) use MLS epochs; broadcast
        // contexts do not use MLS and have no meaningful epoch.
        let epoch = if ctx.broadcast_context.is_none() {
            Some(ctx.epoch.mls_epoch)
        } else {
            None
        };

        let canonical_hash = scp_event_log::checkpoint::compute_checkpoint_canonical_hash(
            context_id,
            sender_did.as_ref(),
            event_count,
            &merkle_root,
            epoch,
            now,
        );

        let signature = ed25519_dalek::Signer::sign(signing_key, &canonical_hash);

        scp_event_log::checkpoint::ConsistencyCheckpoint {
            context_id: context_id.to_owned(),
            sender_did: sender_did.clone(),
            event_count,
            merkle_root,
            epoch,
            timestamp: now,
            signature: signature.to_bytes().to_vec(),
        }
    }

    /// Compares a remote checkpoint against local event log state for
    /// equivocation detection (§9.9.3, ADR-011 AC-8).
    ///
    /// Before comparing Merkle roots, verifies:
    /// 1. The checkpoint sender is a member of this context.
    /// 2. The checkpoint's Ed25519 signature is valid (via key resolver).
    ///
    /// When the comparison returns `Divergent`, emits an
    /// [`ContextEvent::EquivocationDetected`] event on the receive buffer
    /// and appends a durable event log entry.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if the context is
    /// not registered.
    /// Returns [`ContextError::MemberNotFound`] if the checkpoint sender
    /// is not a member of the context.
    /// Returns [`ContextError::CryptoFailed`] if the public key cannot be
    /// resolved or the Ed25519 signature verification fails.
    #[instrument(skip_all, fields(context_id))]
    pub async fn compare_remote_checkpoint(
        &self,
        context_id: &str,
        remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
    ) -> Result<scp_event_log::checkpoint::CheckpointComparison, ContextError> {
        // Verify the sender is a member of this context.
        {
            let contexts = self.contexts.lock().await;
            let ctx = contexts
                .get(context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            if !ctx.membership.contains(remote.sender_did.as_ref()) {
                return Err(ContextError::MemberNotFound(format!(
                    "checkpoint sender {} is not a member of context {context_id}",
                    remote.sender_did
                )));
            }
        }

        // Verify checkpoint Ed25519 signature.
        let sender_pk = (self.key_resolver)(&remote.sender_did).ok_or_else(|| {
            ContextError::CryptoFailed(format!(
                "cannot resolve public key for checkpoint sender {}",
                remote.sender_did
            ))
        })?;
        scp_event_log::checkpoint::verify_checkpoint_signature(remote, &sender_pk).map_err(
            |reason| {
                ContextError::CryptoFailed(format!(
                    "checkpoint signature verification failed: {reason}"
                ))
            },
        )?;

        let context_id_bytes = super::context_id_to_bytes(context_id);
        let local_root = self
            .event_log
            .event_log_merkle_root(&context_id_bytes)
            .unwrap_or([0u8; 32]);
        let local_count = self
            .event_log
            .event_log_entries(&context_id_bytes)
            .ok()
            .flatten()
            .map_or(0, |e| e.len() as u64);

        // Note: `prove_consistency` is NOT used here because consistency
        // proofs prove that a smaller version of the SAME log is a prefix
        // of a larger version. Cross-member equivocation detection compares
        // two DIFFERENT logs from different members — Merkle root comparison
        // is the correct mechanism (identical roots ⇒ identical event
        // sequences, per second-preimage resistance of SHA-256).
        let comparison = match local_count.cmp(&remote.event_count) {
            std::cmp::Ordering::Equal => {
                if local_root == remote.merkle_root {
                    scp_event_log::checkpoint::CheckpointComparison::Consistent
                } else {
                    scp_event_log::checkpoint::CheckpointComparison::Divergent {
                        first_divergent_event: None,
                    }
                }
            }
            std::cmp::Ordering::Less => scp_event_log::checkpoint::CheckpointComparison::Behind {
                missing_events: remote.event_count - local_count,
            },
            std::cmp::Ordering::Greater => scp_event_log::checkpoint::CheckpointComparison::Ahead {
                extra_events: local_count - remote.event_count,
            },
        };

        // Emit EquivocationDetected event when divergent.
        if matches!(
            comparison,
            scp_event_log::checkpoint::CheckpointComparison::Divergent { .. }
        ) {
            tracing::warn!(
                context_id,
                remote_sender = %remote.sender_did,
                event_count = remote.event_count,
                "relay equivocation detected — divergent Merkle roots at same event count (§9.9.3)"
            );
            if let Err(e) = self.event_log.append_context_event(
                &context_id_bytes,
                "EquivocationDetected",
                remote.sender_did.as_ref(),
            ) {
                tracing::warn!(
                    context_id,
                    "failed to append EquivocationDetected to event log: {e}"
                );
            }
            let mut contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get_mut(context_id) {
                super::append_to_merkle_tree(
                    &mut ctx.merkle_tree,
                    "EquivocationDetected",
                    remote.sender_did.as_ref(),
                );
                ctx.receive_buffer.push(ContextEvent::EquivocationDetected {
                    context_id: context_id.to_owned(),
                    remote_sender_did: remote.sender_did.clone(),
                    event_count: remote.event_count,
                });
            }
        }

        Ok(comparison)
    }

    // -------------------------------------------------------------------
    // Merkle tree synchronization
    // -------------------------------------------------------------------

    /// Synchronizes the per-context Merkle tree with the `MerkleEventLogProvider`.
    ///
    /// Compares the Merkle tree's event count with the provider's entry count
    /// and replays any missing entries via `push_leaf_raw`. This lazy sync
    /// ensures proof functions always operate on a complete tree even when
    /// individual `append_context_event` call sites didn't explicitly append
    /// to the Merkle tree.
    ///
    /// Called by [`prove_event_inclusion`] and [`prove_event_consistency`]
    /// before generating proofs.
    fn sync_merkle_tree(&self, context_id: &str, ctx: &mut super::PerContextState) {
        let context_id_bytes = super::context_id_to_bytes(context_id);
        // event_count returns u64; on 32-bit targets the log size is bounded
        // by available memory well below u32::MAX, so saturating is safe.
        let tree_count = usize::try_from(scp_event_log::tree::event_count(&ctx.merkle_tree))
            .unwrap_or(usize::MAX);

        if let Ok(Some(entries)) = self.event_log.event_log_entries(&context_id_bytes)
            && entries.len() > tree_count
        {
            // Replay missing entries. Each entry's pre-computed hash is
            // pushed as a raw leaf — the internal tree structure (RFC 6962
            // interior nodes) is rebuilt automatically by `push_leaf_raw`.
            for entry in entries.iter().skip(tree_count) {
                ctx.merkle_tree.push_leaf_raw(entry.hash);
            }
        }
    }

    // -------------------------------------------------------------------
    // Merkle proof operations (ADR-011, #1535)
    // -------------------------------------------------------------------

    /// Returns a Merkle inclusion proof for the event at the given index
    /// in the per-context RFC 6962 event log.
    ///
    /// The proof consists of sibling hashes at each tree level from the leaf
    /// up to the root. Proof size is O(log n). Verifiable via
    /// [`verify_event_inclusion`](Self::verify_event_inclusion).
    ///
    /// See ADR-011 acceptance criterion 3.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if the context is unknown.
    /// Returns [`ContextError::EventLogFailed`] if the leaf index is out of
    /// bounds or the log is empty.
    pub async fn prove_event_inclusion(
        &self,
        context_id: &str,
        leaf_index: u64,
    ) -> Result<scp_event_log::proof::InclusionProof, ContextError> {
        let mut contexts = self.contexts.lock().await;
        let ctx = contexts
            .get_mut(context_id)
            .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        self.sync_merkle_tree(context_id, ctx);
        scp_event_log::proof::prove_inclusion(&ctx.merkle_tree, leaf_index)
            .map_err(|e| ContextError::EventLogFailed(e.to_string()))
    }

    /// Returns a Merkle consistency proof between the tree at `old_size` and
    /// the current tree size, proving that the old tree is a prefix of the
    /// current tree (CT-style per RFC 6962).
    ///
    /// See ADR-011 acceptance criterion 5.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if the context is unknown.
    /// Returns [`ContextError::EventLogFailed`] if `old_size` is 0, exceeds
    /// the current size, or the log is empty.
    pub async fn prove_event_consistency(
        &self,
        context_id: &str,
        old_size: u64,
    ) -> Result<scp_event_log::proof::ConsistencyProof, ContextError> {
        let mut contexts = self.contexts.lock().await;
        let ctx = contexts
            .get_mut(context_id)
            .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        self.sync_merkle_tree(context_id, ctx);
        let current_size = scp_event_log::tree::event_count(&ctx.merkle_tree);
        scp_event_log::proof::prove_consistency(&ctx.merkle_tree, old_size, current_size)
            .map_err(|e| ContextError::EventLogFailed(e.to_string()))
    }

    /// Verifies a Merkle inclusion proof. Pure function — no state needed.
    ///
    /// Recomputes the root hash from the proof path and compares against the
    /// stated root using constant-time comparison.
    ///
    /// See ADR-011 acceptance criterion 5.
    #[must_use]
    pub fn verify_event_inclusion(proof: &scp_event_log::proof::InclusionProof) -> bool {
        scp_event_log::proof::verify_inclusion(proof)
    }

    /// Verifies a Merkle consistency proof. Pure function — no state needed.
    ///
    /// Reconstructs both the old and new roots from the stored leaf hashes
    /// and verifies they match the stated roots.
    ///
    /// See RFC 6962 Section 2.1.2.
    #[must_use]
    pub fn verify_event_consistency(proof: &scp_event_log::proof::ConsistencyProof) -> bool {
        scp_event_log::proof::verify_consistency(proof)
    }
}
