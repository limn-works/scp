//! Simple queries and local DID management.
//!
//! # Hoist (ADR-049 commit 12c.5)
//!
//! Every query-domain method body lives in the sibling
//! [`crate::context::queries_helpers`] module; the inherent methods on
//! [`ContextManager`] here are one-line forwarders during the
//! commits-10-to-12 shim window. They are deleted alongside the outer
//! shim in a later ADR-049 commit when the actor handler bodies own
//! the queries path directly.
//!
//! Methods that are **not hoisted** and remain as real inherent bodies
//! here:
//!
//! - `set_payment_adapter` — `&mut self` one-time setter used only by
//!   the builder and integration-test wiring; not reached from actor
//!   handlers and does not fit the free-function pattern.
//! - `event_log_provider` — pure accessor returning
//!   `&dyn ContextEventLogProvider`. The modern accessor is
//!   [`ContextManager::event_log_ref`]. Retained for FFI-bridge
//!   backwards compatibility.

use super::{
    Arc, CommitFaultMarker, ContextError, ContextEventLogProvider, ContextManager, ContextParams,
    ContextRoleState, DID, PendingCommit, RoleAssignment, Zeroizing, instrument,
};

#[allow(clippy::significant_drop_tightening)]
impl ContextManager {
    /// Registers a DID as controlled by the local node/SDK.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::register_local_did`] free
    /// function (ADR-049 commit 12c.5).
    #[instrument(skip_all)]
    pub async fn register_local_did(&self, did: DID) {
        crate::context::queries_helpers::register_local_did(self, did).await;
    }

    /// Sets the payment adapter for the 9-step paid action flow (spec §19.2.2).
    ///
    /// When set, `authorize_paid_action`→`complete_paid_action` runs the
    /// full escrow sequence for each paid entry point (`send_message`,
    /// `join_context`, `invoke_tool`). When `None`, those entry points
    /// still enforce budget tracking but skip the payment rail integration.
    ///
    /// Can be called at any time; takes effect for subsequent actions.
    ///
    /// Not hoisted — `&mut self` one-time setter structurally outside
    /// the free-function hoist pattern (ADR-049 commit 12c.5).
    pub fn set_payment_adapter(
        &mut self,
        adapter: Arc<dyn crate::economy::adapter::PaymentAdapterDyn>,
    ) {
        self.payment_adapter = Some(adapter);
    }

    /// Returns `true` if the given DID is registered as locally controlled.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::is_local_did`] free function
    /// (ADR-049 commit 12c.5).
    #[instrument(skip_all)]
    pub async fn is_local_did(&self, did: &DID) -> bool {
        crate::context::queries_helpers::is_local_did(self, did).await
    }

    /// Returns the local member's pseudonym routing ID for a context (§9.10.4).
    ///
    /// Returns `None` if no pseudonym was set (legacy callers, broadcast contexts).
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::local_pseudonym`] free function
    /// (ADR-049 commit 12c.5).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if the context is not registered.
    pub async fn local_pseudonym(
        &self,
        context_id: &str,
    ) -> Result<Option<[u8; 32]>, ContextError> {
        crate::context::queries_helpers::local_pseudonym(self, context_id).await
    }

    /// Returns the broadcast key and epoch for a locally controlled author
    /// in a broadcast context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::get_broadcast_key_for_local_author`]
    /// free function (ADR-049 commit 12c.5).
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
        crate::context::queries_helpers::get_broadcast_key_for_local_author(
            self, context_id, author_did,
        )
        .await
    }

    /// Returns the current member count for a context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::member_count`] free function
    /// (ADR-049 commit 12c.5).
    #[instrument(skip_all, fields(context_id))]
    pub async fn member_count(&self, context_id: &str) -> Option<usize> {
        crate::context::queries_helpers::member_count(self, context_id).await
    }

    /// Returns `true` if the given DID is a member of the specified context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::is_member`] free function
    /// (ADR-049 commit 12c.5).
    #[instrument(skip_all, fields(context_id))]
    pub async fn is_member(&self, context_id: &str, did: &str) -> bool {
        crate::context::queries_helpers::is_member(self, context_id, did).await
    }

    /// Returns all member DIDs for a context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::member_dids`] free function
    /// (ADR-049 commit 12c.5).
    #[instrument(skip_all, fields(context_id))]
    pub async fn member_dids(&self, context_id: &str) -> Vec<String> {
        crate::context::queries_helpers::member_dids(self, context_id).await
    }

    /// Returns the role assignment for a specific member in a context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::member_role`] free function
    /// (ADR-049 commit 12c.5).
    #[instrument(skip_all, fields(context_id))]
    pub async fn member_role(&self, context_id: &str, did: &str) -> Option<RoleAssignment> {
        crate::context::queries_helpers::member_role(self, context_id, did).await
    }

    /// Returns a clone of the context's creation parameters, or `None` if the
    /// context is not registered with this manager.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::context_params`] free function
    /// (ADR-049 commit 12c.5).
    #[instrument(skip_all, fields(context_id))]
    pub async fn context_params(&self, context_id: &str) -> Option<ContextParams> {
        crate::context::queries_helpers::context_params(self, context_id).await
    }

    /// Returns a clone of the role state for a context, or `None` if the
    /// context is not registered.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::get_role_state`] free function
    /// (ADR-049 commit 12c.5).
    #[instrument(skip_all, fields(context_id))]
    pub async fn get_role_state(&self, context_id: &str) -> Option<ContextRoleState> {
        crate::context::queries_helpers::get_role_state(self, context_id).await
    }

    /// Drains all events from the receive buffer for a context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::drain_events`] free function
    /// (ADR-049 commit 12c.5).
    #[instrument(skip_all, fields(context_id))]
    pub async fn drain_events(
        &self,
        context_id: &str,
    ) -> Vec<scp_protocol::context::membership::ContextEvent> {
        crate::context::queries_helpers::drain_events(self, context_id).await
    }

    /// Returns the Merkle event log entries for a context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::event_log_entries`] free function
    /// (ADR-049 commit 12c.5).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the event log provider fails.
    pub fn event_log_entries(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Option<Vec<crate::context::providers::event_log::EventLogEntry>>, ContextError>
    {
        crate::context::queries_helpers::event_log_entries(self, context_id)
    }

    /// Returns the event log provider for direct Merkle tree access.
    ///
    /// Primarily intended for the FFI layer to query event counts and
    /// Merkle roots without duplicating event log state.
    ///
    /// Not hoisted — pure accessor returning a borrow of the manager's
    /// event log provider. The modern accessor is
    /// [`Self::event_log_ref`]. Retained for FFI-bridge backwards
    /// compatibility (ADR-049 commit 12c.5).
    pub fn event_log_provider(&self) -> &dyn ContextEventLogProvider {
        self.event_log.as_ref()
    }

    /// Reports that a received envelope triggered degraded mode (§13.6) for a
    /// context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::report_degraded_mode`] free
    /// function (ADR-049 commit 12c.5).
    #[instrument(skip_all, fields(context_id))]
    pub async fn report_degraded_mode(
        &self,
        context_id: &str,
        compat: scp_protocol::envelope::VersionCompatibility,
        unsupported_features: Vec<String>,
    ) {
        crate::context::queries_helpers::report_degraded_mode(
            self,
            context_id,
            compat,
            unsupported_features,
        )
        .await;
    }

    /// Generates and stores a per-member access key for explicit lifecycle
    /// management.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::generate_context_access_key`] free
    /// function (ADR-049 commit 12c.5).
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
        crate::context::queries_helpers::generate_context_access_key(
            self, context_id, member_did, caller_did,
        )
        .await
    }

    /// Revokes (removes) a member's access key from the context's access
    /// key store.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::revoke_context_access_key`] free
    /// function (ADR-049 commit 12c.5).
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
        crate::context::queries_helpers::revoke_context_access_key(
            self, context_id, member_did, caller_did,
        )
        .await
    }

    /// Restores a member's access key by generating a new key at epoch 0.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::restore_context_access_key`] free
    /// function (ADR-049 commit 12c.5).
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
        crate::context::queries_helpers::restore_context_access_key(
            self, context_id, member_did, caller_did,
        )
        .await
    }

    /// Stores an access key in a context's access key store.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::set_access_key`] free function
    /// (ADR-049 commit 12c.5).
    #[instrument(skip_all, fields(context_id, member_did))]
    pub async fn set_access_key(
        &self,
        context_id: &str,
        member_did: &str,
        key: scp_protocol::crypto::access_keys::AccessKey,
    ) {
        crate::context::queries_helpers::set_access_key(self, context_id, member_did, key).await;
    }

    /// Removes a member's access key from a context's access key store.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::remove_access_key`] free function
    /// (ADR-049 commit 12c.5).
    #[instrument(skip_all, fields(context_id, member_did))]
    pub async fn remove_access_key(&self, context_id: &str, member_did: &str) {
        crate::context::queries_helpers::remove_access_key(self, context_id, member_did).await;
    }

    /// Injects an access key into a context's access key store.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// `crate::context::queries_helpers::inject_access_key` free function
    /// (ADR-049 commit 12c.5).
    #[cfg(feature = "testing")]
    pub async fn inject_access_key(
        &self,
        context_id: &str,
        member_did: &str,
        key: scp_protocol::crypto::access_keys::AccessKey,
    ) {
        crate::context::queries_helpers::inject_access_key(self, context_id, member_did, key).await;
    }

    /// Retrieves a clone of the access key for a member in a context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// `crate::context::queries_helpers::get_access_key` free function
    /// (ADR-049 commit 12c.5).
    #[cfg(feature = "testing")]
    pub async fn get_access_key(
        &self,
        context_id: &str,
        member_did: &str,
    ) -> Option<scp_protocol::crypto::access_keys::AccessKey> {
        crate::context::queries_helpers::get_access_key(self, context_id, member_did).await
    }

    /// Retrieves clones of ALL access keys for a context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// `crate::context::queries_helpers::get_all_access_keys` free function
    /// (ADR-049 commit 12c.5).
    #[cfg(feature = "testing")]
    pub async fn get_all_access_keys(
        &self,
        context_id: &str,
    ) -> std::collections::HashMap<String, scp_protocol::crypto::access_keys::AccessKey> {
        crate::context::queries_helpers::get_all_access_keys(self, context_id).await
    }

    /// Grants budget to a member in a context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// `crate::context::queries_helpers::grant_budget_for_test` free function
    /// (ADR-049 commit 12c.5).
    #[cfg(feature = "testing")]
    pub async fn grant_budget_for_test(
        &self,
        context_id: &str,
        member_did: &scp_identity::DID,
        amount: scp_protocol::economy::types::Amount,
    ) {
        crate::context::queries_helpers::grant_budget_for_test(
            self, context_id, member_did, amount,
        )
        .await;
    }

    /// Returns the remaining budget for a member in a context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// `crate::context::queries_helpers::remaining_budget_for_test` free
    /// function (ADR-049 commit 12c.5).
    #[cfg(feature = "testing")]
    pub async fn remaining_budget_for_test(
        &self,
        context_id: &str,
        member_did: &scp_identity::DID,
    ) -> scp_protocol::economy::types::Amount {
        crate::context::queries_helpers::remaining_budget_for_test(self, context_id, member_did)
            .await
    }

    /// Returns the per-DID velocity (number of recent paid actions) for
    /// a member in a context within the velocity window.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// `crate::context::queries_helpers::velocity_for_test` free function
    /// (ADR-049 commit 12c.5).
    #[cfg(feature = "testing")]
    pub async fn velocity_for_test(
        &self,
        context_id: &str,
        member_did: &scp_identity::DID,
        now_secs: u64,
    ) -> u64 {
        crate::context::queries_helpers::velocity_for_test(self, context_id, member_did, now_secs)
            .await
    }

    /// Returns a clone of the persistent MLS Commit retry queue for a context
    /// (PR #1606 C6).
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::pending_commits`] free function
    /// (ADR-049 commit 12c.5).
    #[instrument(skip_all, fields(context_id))]
    pub async fn pending_commits(&self, context_id: &str) -> Vec<PendingCommit> {
        crate::context::queries_helpers::pending_commits(self, context_id).await
    }

    /// Returns the active commit fault marker for a context, if any (PR #1606 C6).
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::commit_fault`] free function
    /// (ADR-049 commit 12c.5).
    #[instrument(skip_all, fields(context_id))]
    pub async fn commit_fault(&self, context_id: &str) -> Option<CommitFaultMarker> {
        crate::context::queries_helpers::commit_fault(self, context_id).await
    }

    // -------------------------------------------------------------------------
    // Checkpoint operations (§9.9.3, ADR-011 AC-8)
    // -------------------------------------------------------------------------

    /// Creates a consistency checkpoint if one is due based on event count
    /// or time interval thresholds.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::create_checkpoint_if_due`] free
    /// function (ADR-049 commit 12c.5).
    pub(crate) fn create_checkpoint_if_due(
        &self,
        context_id: &str,
        ctx: &mut super::PerContextState,
        sender_did: &DID,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Option<scp_event_log::checkpoint::ConsistencyCheckpoint> {
        crate::context::queries_helpers::create_checkpoint_if_due(
            self,
            context_id,
            ctx,
            sender_did,
            signing_key,
        )
    }

    /// Unconditionally creates a consistency checkpoint regardless of whether
    /// the event/time thresholds have been reached.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::force_create_checkpoint`] free
    /// function (ADR-049 commit 12c.5).
    pub(crate) fn force_create_checkpoint(
        &self,
        context_id: &str,
        ctx: &mut super::PerContextState,
        sender_did: &DID,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> scp_event_log::checkpoint::ConsistencyCheckpoint {
        crate::context::queries_helpers::force_create_checkpoint(
            self,
            context_id,
            ctx,
            sender_did,
            signing_key,
        )
    }

    /// Compares a remote checkpoint against local event log state for
    /// equivocation detection (§9.9.3, ADR-011 AC-8).
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::compare_remote_checkpoint`] free
    /// function (ADR-049 commit 12c.5).
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
        crate::context::queries_helpers::compare_remote_checkpoint(self, context_id, remote).await
    }

    // -------------------------------------------------------------------
    // Merkle proof operations (ADR-011, #1535)
    // -------------------------------------------------------------------

    /// Returns a Merkle inclusion proof for the event at the given index
    /// in the per-context RFC 6962 event log.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::prove_event_inclusion`] free
    /// function (ADR-049 commit 12c.5).
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
        crate::context::queries_helpers::prove_event_inclusion(self, context_id, leaf_index).await
    }

    /// Returns a Merkle consistency proof between the tree at `old_size` and
    /// the current tree size, proving that the old tree is a prefix of the
    /// current tree (CT-style per RFC 6962).
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::prove_event_consistency`] free
    /// function (ADR-049 commit 12c.5).
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
        crate::context::queries_helpers::prove_event_consistency(self, context_id, old_size).await
    }

    /// Verifies a Merkle inclusion proof. Pure function — no state needed.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::verify_event_inclusion`] free
    /// function (ADR-049 commit 12c.5).
    #[must_use]
    pub fn verify_event_inclusion(proof: &scp_event_log::proof::InclusionProof) -> bool {
        crate::context::queries_helpers::verify_event_inclusion(proof)
    }

    /// Verifies a Merkle consistency proof. Pure function — no state needed.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::queries_helpers::verify_event_consistency`] free
    /// function (ADR-049 commit 12c.5).
    #[must_use]
    pub fn verify_event_consistency(proof: &scp_event_log::proof::ConsistencyProof) -> bool {
        crate::context::queries_helpers::verify_event_consistency(proof)
    }
}
