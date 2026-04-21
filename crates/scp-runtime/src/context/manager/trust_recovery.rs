//! Trust verification, attestation, checkpoints, and recovery.
//!
//! The five `ContextManager` methods reached by the trust-recovery actor
//! handler (`create_governance_checkpoint`, `add_checkpoint_cosignature`,
//! `recovery_advance_epoch`, `recovery_send_notification`,
//! `recovery_notify_contact`) now forward to hoisted `pub async fn` free
//! functions in [`crate::context::trust_recovery_helpers`] (ADR-049 commit
//! 12c.3). The three pure-CPU trust methods (`verify_attestation`,
//! `create_challenge`, `verify_challenge_response`) remain as inherent
//! methods here — they are not reached by any actor command.

use super::{
    CheckpointAttestationStatus, ContextCheckpoint, ContextError, ContextManager,
    CosignedCheckpoint, DID, instrument,
};

impl ContextManager {
    /// Verifies an attestation chain (Layer 3) using the production DID
    /// public key resolver.
    ///
    /// Delegates to [`scp_protocol::trust::verify_attestation`] with
    /// [`scp_protocol::trust::IdentityDidPublicKeyResolver`] for key resolution.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] wrapping the underlying [`scp_protocol::trust::TrustError`] if
    /// signature verification, expiry checks, or revocation checks fail.
    pub fn verify_attestation(
        &self,
        attestation: &scp_protocol::trust::Attestation,
    ) -> Result<(), ContextError> {
        let resolver = scp_protocol::trust::IdentityDidPublicKeyResolver;
        scp_protocol::trust::verify_attestation(attestation, &resolver, &*self.clock).map_err(|e| {
            ContextError::PermissionDenied(format!("attestation verification failed: {e}"))
        })
    }

    /// Issues a challenge request (Layer 3 — Challenge-Response) using the
    /// production DID resolver.
    ///
    /// Delegates to [`scp_protocol::trust::issue_challenge`] to construct and sign
    /// a challenge request.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if signing fails.
    #[allow(clippy::too_many_arguments)]
    pub fn create_challenge(
        &self,
        challenger_did: &DID,
        subject_did: &DID,
        challenge_type: scp_protocol::trust::ChallengeType,
        capability_uri: String,
        params: serde_json::Value,
        timeout: std::time::Duration,
        signer: &impl scp_protocol::trust::ChallengeSigner,
    ) -> Result<scp_protocol::trust::ChallengeRequest, ContextError> {
        scp_protocol::trust::issue_challenge(
            challenger_did.clone(),
            subject_did.clone(),
            challenge_type,
            capability_uri,
            params,
            timeout,
            signer,
        )
        .map_err(|e| ContextError::PermissionDenied(format!("challenge creation failed: {e}")))
    }

    /// Verifies a challenge response (Layer 3 — Challenge-Response) using the
    /// production DID resolver.
    ///
    /// Delegates to [`scp_protocol::trust::verify_challenge_response`] with
    /// [`scp_protocol::trust::IdentityDidPublicKeyResolver`] for key resolution.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] wrapping the underlying [`scp_protocol::trust::TrustError`] if
    /// verification fails.
    pub fn verify_challenge_response(
        &self,
        request: &scp_protocol::trust::ChallengeRequest,
        response: &scp_protocol::trust::ChallengeResponse,
        verifier_signer: &impl scp_protocol::trust::ChallengeSigner,
        context_id: Option<String>,
    ) -> Result<scp_protocol::trust::ChallengeVerification, ContextError> {
        let resolver = scp_protocol::trust::IdentityDidPublicKeyResolver;
        scp_protocol::trust::verify_challenge_response(
            request,
            response,
            &resolver,
            &*self.clock,
            verifier_signer,
            context_id,
        )
        .map_err(|e| ContextError::PermissionDenied(format!("challenge verification failed: {e}")))
    }

    /// Creates a governance-aware checkpoint for a context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::trust_recovery_helpers::create_governance_checkpoint`]
    /// free function (ADR-049 commit 12c.3). Deleted in a later commit
    /// alongside every other `ContextManager` trust-recovery surface.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip_all, fields(context_id))]
    pub async fn create_governance_checkpoint(
        &self,
        context_id: &str,
        checkpoint_seq: u64,
        merkle_root: [u8; 32],
        event_count: u64,
        last_event_hash: [u8; 32],
        state_snapshot_hash: [u8; 32],
        creator_did: &DID,
        creator_signature: Vec<u8>,
    ) -> Result<ContextCheckpoint, ContextError> {
        crate::context::trust_recovery_helpers::create_governance_checkpoint(
            self,
            context_id,
            checkpoint_seq,
            merkle_root,
            event_count,
            last_event_hash,
            state_snapshot_hash,
            creator_did,
            creator_signature,
        )
        .await
    }

    /// Adds a cosignature to an existing checkpoint and re-evaluates
    /// attestation status.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::trust_recovery_helpers::add_checkpoint_cosignature`]
    /// free function (ADR-049 commit 12c.3).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    /// - [`ContextError::GovernanceFailed`] if the cosignature validation fails.
    #[instrument(skip_all, fields(context_id))]
    pub async fn add_checkpoint_cosignature(
        &self,
        context_id: &str,
        checkpoint: &mut ContextCheckpoint,
        cosignature: CosignedCheckpoint,
    ) -> Result<CheckpointAttestationStatus, ContextError> {
        crate::context::trust_recovery_helpers::add_checkpoint_cosignature(
            self,
            context_id,
            checkpoint,
            cosignature,
        )
        .await
    }

    /// Advances the MLS epoch for a context as part of compromise recovery
    /// (spec §9.12 step 2).
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::trust_recovery_helpers::recovery_advance_epoch`]
    /// free function (ADR-049 commit 12c.3).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::CryptoFailed`] if the MLS update/commit fails.
    #[instrument(skip_all, fields(context_id))]
    pub async fn recovery_advance_epoch(&self, context_id: &str) -> Result<u64, ContextError> {
        crate::context::trust_recovery_helpers::recovery_advance_epoch(self, context_id).await
    }

    /// Sends an encrypted message to a context for recovery notification
    /// purposes (spec §9.12 step 5).
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::trust_recovery_helpers::recovery_send_notification`]
    /// free function (ADR-049 commit 12c.3).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::TransportFailed`] if the message cannot be sent.
    #[instrument(skip_all, fields(context_id))]
    pub async fn recovery_send_notification(
        &self,
        context_id: &str,
        sender_did: &str,
        payload: &[u8],
        sequence: u64,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), ContextError> {
        crate::context::trust_recovery_helpers::recovery_send_notification(
            self,
            context_id,
            sender_did,
            payload,
            sequence,
            signing_key,
        )
        .await
    }

    /// Sends a recovery notification to a contact DID by finding shared
    /// contexts where both the recovering DID and the contact are members,
    /// then sending the notification through the first matching context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::trust_recovery_helpers::recovery_notify_contact`]
    /// free function (ADR-049 commit 12c.3).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::TransportFailed`] if no shared context is found
    /// or the message cannot be sent.
    #[instrument(skip_all, fields(context_id))]
    pub async fn recovery_notify_contact(
        &self,
        recovering_did: &str,
        contact_did: &str,
        payload: &[u8],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), ContextError> {
        crate::context::trust_recovery_helpers::recovery_notify_contact(
            self,
            recovering_did,
            contact_did,
            payload,
            signing_key,
        )
        .await
    }
}
