//! Simple queries and local DID management.

use super::{
    ContextError, ContextEvent, ContextEventLogProvider, ContextManager, ContextParams,
    ContextRoleState, DID, RoleAssignment, Zeroizing, instrument,
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
}
