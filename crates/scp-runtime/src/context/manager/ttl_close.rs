//! TTL management and context close operations.
//!
//! # Lifecycle / `ttl_close` hoist (commit 12c.2 of ADR-049)
//!
//! Every inherent method in this file is a one-line forwarder to a
//! corresponding free function in
//! [`crate::context::lifecycle_helpers`] with explicit-collaborator
//! signatures. The outer shim (including every forwarder in this file)
//! is deleted in a later ADR-049 commit once the actor handler bodies
//! in [`crate::context::actor::handlers::ttl_close`] own the TTL / close
//! path.

use super::{CloseResult, ContextError, ContextHandle, ContextManager, DID, instrument};

impl ContextManager {
    /// Initiates cooperative context closure.
    ///
    /// For `SingleAdmin` governance: verifies the initiator has the
    /// `ContextClose` capability, transitions from `Active` to `Closing`,
    /// and appends a `ContextClosing` event. Cancels any active TTL timer.
    ///
    /// For multi-admin governance models (`Threshold`, `Majority`,
    /// `Unanimity`): returns `PermissionDenied`. Multi-admin contexts MUST
    /// close through the governance path: `propose_governance_action` with
    /// `GovernanceAction::CloseContext` -> vote -> auto-execute on approval
    /// (SCP-270, ADR-031). This ensures all signers/voters can participate
    /// in the close decision.
    ///
    /// See ADR-008 acceptance criterion 5.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotActive`] if the context is not
    /// `Active`. Returns [`ContextError::PermissionDenied`] if the context
    /// uses a multi-admin governance model (use governance proposal path
    /// instead) or if the initiator lacks `ContextClose` capability.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::close_context`] free function
    /// (ADR-049 commit 12c.2). Deleted in a later commit alongside every
    /// other `ContextManager` lifecycle surface.
    #[instrument(skip_all, fields(context_id = handle.context_id()))]
    pub async fn close_context(
        &self,
        handle: &ContextHandle,
        initiator_did: &DID,
    ) -> Result<CloseResult, ContextError> {
        crate::context::lifecycle_helpers::close_context(self, handle, initiator_did).await
    }

    /// Closes a context with an optional signing key for final checkpoint
    /// generation (§9.9.3).
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::close_context_with_key`] free
    /// function (ADR-049 commit 12c.2). Deleted in a later commit
    /// alongside every other `ContextManager` lifecycle surface.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotActive`] if the context is not
    /// `Active`. Returns [`ContextError::PermissionDenied`] if the context
    /// uses a multi-admin governance model or the initiator lacks
    /// `ContextClose` capability.
    pub async fn close_context_with_key(
        &self,
        handle: &ContextHandle,
        initiator_did: &DID,
        signing_key: Option<&ed25519_dalek::SigningKey>,
    ) -> Result<CloseResult, ContextError> {
        crate::context::lifecycle_helpers::close_context_with_key(
            self,
            handle,
            initiator_did,
            signing_key,
        )
        .await
    }

    /// Completes context closure.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::finalize_close`] free function
    /// (ADR-049 commit 12c.2). Deleted in a later commit alongside every
    /// other `ContextManager` lifecycle surface.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the context is not in `Closing` state
    /// or if destruction operations fail.
    #[instrument(skip_all, fields(context_id = handle.context_id()))]
    pub async fn finalize_close(&self, handle: &ContextHandle) -> Result<(), ContextError> {
        crate::context::lifecycle_helpers::finalize_close(self, handle).await
    }

    /// Handles automatic TTL expiry.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::handle_ttl_expiry`] free
    /// function (ADR-049 commit 12c.2). Deleted in a later commit
    /// alongside every other `ContextManager` lifecycle surface.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotActive`] if the context is not
    /// in `Active` state.
    #[instrument(skip_all, fields(context_id = handle.context_id()))]
    pub async fn handle_ttl_expiry(&self, handle: &ContextHandle) -> Result<(), ContextError> {
        crate::context::lifecycle_helpers::handle_ttl_expiry(self, handle).await
    }

    /// Proposes a TTL extension. Records consent from the given member.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::propose_ttl_extension`] free
    /// function (ADR-049 commit 12c.2). Deleted in a later commit
    /// alongside every other `ContextManager` lifecycle surface.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::MembershipFailed`] if the context is not
    /// registered. Returns [`ContextError::MemberNotFound`] if the member
    /// is not in the context.
    #[instrument(skip_all, fields(context_id))]
    pub async fn propose_ttl_extension(
        &self,
        context_id: &str,
        member_did: &DID,
        proposed_duration: std::time::Duration,
    ) -> Result<bool, ContextError> {
        crate::context::lifecycle_helpers::propose_ttl_extension(
            self,
            context_id,
            member_did,
            proposed_duration,
        )
        .await
    }

    /// Resets the TTL timer after a successful unanimous extension.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::reset_ttl_timer`] free
    /// function (ADR-049 commit 12c.2). Deleted in a later commit
    /// alongside every other `ContextManager` lifecycle surface.
    #[instrument(skip_all, fields(context_id))]
    pub async fn reset_ttl_timer(
        &self,
        context_id: &str,
        new_duration: std::time::Duration,
        handle: ContextHandle,
    ) {
        crate::context::lifecycle_helpers::reset_ttl_timer(self, context_id, new_duration, handle)
            .await;
    }

    /// Spawns a TTL timer for the given context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::spawn_ttl_timer`] free
    /// function (ADR-049 commit 12c.2). Deleted in a later commit
    /// alongside every other `ContextManager` lifecycle surface.
    pub(crate) async fn spawn_ttl_timer(
        &self,
        context_id: &str,
        duration: std::time::Duration,
        handle: ContextHandle,
    ) {
        crate::context::lifecycle_helpers::spawn_ttl_timer(self, context_id, duration, handle)
            .await;
    }
}
