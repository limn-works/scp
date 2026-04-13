//! Trust verification, attestation, checkpoints, and recovery.

use super::{
    Arc, CheckpointAttestationStatus, ContextCheckpoint, ContextError, ContextManager,
    CosignedCheckpoint, DID, Mutex, PerContextState, context_id_to_bytes, instrument,
    require_active,
};

#[allow(clippy::significant_drop_tightening)]
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
    /// Constructs a [`ContextCheckpoint`] signed by the creator and queries
    /// the governance engine for cosignature requirements. For `SingleAdmin`,
    /// the checkpoint is immediately `FullyAttested`. For multi-admin models,
    /// it starts as `PartiallyAttested` until sufficient cosignatures are
    /// collected via [`add_checkpoint_cosignature`](Self::add_checkpoint_cosignature).
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
        let ctx_arc = self
            .get_context_arc(context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;
        require_active(&ctx.handle)?;

        let (_, min_count) = ctx.governance.engine.checkpoint_cosignature_requirements();
        let attestation_status = if min_count == 0 {
            CheckpointAttestationStatus::FullyAttested
        } else {
            CheckpointAttestationStatus::PartiallyAttested
        };

        // Capture pruning policy before dropping the lock.
        let pruning_policy = ctx.governance.pruning_policy.clone();

        let created_at = self.clock.now_secs();

        let checkpoint = ContextCheckpoint {
            checkpoint_seq,
            merkle_root,
            event_count,
            last_event_hash,
            state_snapshot_hash,
            created_at,
            creator_did: creator_did.clone(),
            creator_signature,
            cosignatures: Vec::new(),
            attestation_status,
        };

        // Drop the contexts lock before pruning to avoid holding it during
        // potentially expensive I/O (persistence writes).

        // Trigger event log pruning if a pruning policy is configured on the
        // context (#1474). Best-effort: log but do not fail the checkpoint
        // creation if pruning encounters an error.
        if let Some(ref policy) = pruning_policy {
            let context_id_bytes = context_id_to_bytes(context_id);
            if self
                .event_log
                .prune_before_checkpoint(&context_id_bytes, event_count, policy)
                .is_some_and(|pruned| pruned > 0)
            {
                tracing::info!(
                    context_id = %context_id,
                    checkpoint_seq = checkpoint_seq,
                    "pruned event log entries after governance checkpoint"
                );
            }
        }

        Ok(checkpoint)
    }

    /// Adds a cosignature to an existing checkpoint and re-evaluates attestation status.
    ///
    /// Validates the cosignature against the governance engine's requirements.
    /// If the quorum is now met, the checkpoint transitions to `FullyAttested`.
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
        use sha2::Digest as _;

        let ctx_arc = self
            .get_context_arc(context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;

        // Validate with a candidate vector first — only mutate checkpoint
        // after validation passes to avoid leaving corrupt state on error.
        let mut candidate = checkpoint.cosignatures.clone();
        candidate.push(cosignature);

        // Compute checkpoint hash for verification
        let mut hasher = sha2::Sha256::new();
        hasher.update(checkpoint.merkle_root);
        hasher.update(checkpoint.checkpoint_seq.to_be_bytes());
        hasher.update(checkpoint.event_count.to_be_bytes());
        let checkpoint_hash: [u8; 32] = hasher.finalize().into();

        let status = ctx
            .governance
            .engine
            .validate_checkpoint_cosignatures(&candidate, &checkpoint_hash)
            .map_err(|e| ContextError::GovernanceFailed(e.to_string()))?;

        // Validation passed — commit the mutation.
        checkpoint.cosignatures = candidate;
        checkpoint.attestation_status = status.clone();
        Ok(status)
    }

    /// Advances the MLS epoch for a context as part of compromise recovery
    /// (spec §9.12 step 2).
    ///
    /// Issues an MLS Update + self-Commit via the crypto provider to ratchet
    /// the group to a new epoch with fresh key material, providing
    /// post-compromise security: the compromised old epoch key becomes
    /// useless for future messages.
    ///
    /// Returns the new epoch number on success.
    ///
    /// # Atomicity
    ///
    /// The crypto operation (`advance_epoch`) is performed **before** the
    /// epoch counter is incremented. If the crypto call fails the counter
    /// stays unchanged, preventing a desync between MLS state and the
    /// bookkeeping counter.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered.
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::CryptoFailed`] if the MLS update/commit fails.
    #[instrument(skip_all, fields(context_id))]
    pub async fn recovery_advance_epoch(&self, context_id: &str) -> Result<u64, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        // 1. Validate the context exists and is active (lock scoped).
        //    Capture generation for confused-deputy detection on reacquire.
        let ctx_gen = {
            let (guard, generation) = self.lock_context(context_id).await?;
            let ctx = &*guard;
            require_active(&ctx.handle)?;
            generation
        };

        // 2. Perform the MLS epoch advance (Update + self-Commit).
        //    If this fails the counter is NOT incremented.
        let epoch_output = self.crypto.advance_epoch(&context_id_bytes)?;

        // 2b. Broadcast the MLS Commit to all members so they can advance
        //     their group epoch and ratchet key material.
        if !epoch_output.commit_bytes.is_empty() {
            let routing_id = scp_protocol::context::context_routing_id(context_id);
            if let Err(e) = self
                .transport
                .send_message(&routing_id, &epoch_output.commit_bytes)
            {
                tracing::warn!(
                    context_id = %context_id,
                    error = %e,
                    "failed to broadcast recovery epoch advance MLS Commit"
                );
            }
        }

        // 3. Increment bookkeeping counter and manage grace store.
        //    Verify generation to detect confused-deputy (context removed
        //    and recreated while we awaited the MLS commit).
        let new_epoch = {
            let mut guard = self.relock_context(&ctx_gen).await?;
            let ctx = &mut *guard;
            // Re-validate after the crypto op to close the TOCTOU window between
            // the active check in step 1 and the counter increment here. A
            // concurrent close_context could have transitioned the handle while
            // we awaited the MLS commit.
            require_active(&ctx.handle)?;
            let old_epoch = ctx.epoch.mls_epoch;
            ctx.epoch.mls_epoch = old_epoch.saturating_add(1);
            let _expired = ctx.epoch.grace_store.add_epoch(old_epoch);
            ctx.epoch.mls_epoch
        };

        // 4. Emit epoch advancement event to event log. Event log failures
        //    are non-fatal — recovery must not be blocked by logging issues.
        if let Err(e) = self.event_log.append_context_event(
            &context_id_bytes,
            "recovery/epoch_advanced",
            "system:recovery",
        ) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to append recovery epoch advancement event to event log"
            );
        }
        {
            if let Ok(mut guard) = self.relock_context(&ctx_gen).await {
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }

        // 5. Persist if configured (best-effort).
        if self.has_persistence()
            && let Ok(guard) = self.relock_context(&ctx_gen).await
        {
            let ctx = &*guard;
            let snapshot = Self::snapshot_context(ctx);
            self.persist_context_snapshot(context_id, snapshot);
        }

        Ok(new_epoch)
    }

    /// Sends an encrypted message to a context for recovery notification
    /// purposes (spec §9.12 step 5).
    ///
    /// This is a thin wrapper around the crypto and transport providers that
    /// encrypts and sends a payload without the full `send_message` validation
    /// pipeline (since recovery may be happening in a degraded state).
    ///
    /// Each recovery step uses a distinct `sequence` number to avoid
    /// collisions when multiple notifications are sent for the same
    /// context and epoch: 0 = MLS epoch-advance, 1 = UCAN revocation,
    /// 2 = key-package rotation, 3 = PSK rotation, 4 = contact notification.
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
        let context_id_bytes = context_id_to_bytes(context_id);

        // Look up the current MLS epoch for this context. After an epoch
        // advance in step 2, the epoch is > 0 — using the real value ensures
        // receivers can validate the message against their local epoch state.
        let current_epoch = {
            if let Some(entry) = self.contexts.get(context_id) {
                let arc = entry.value().clone();
                drop(entry);
                let ctx = arc.lock().await;
                ctx.epoch.mls_epoch
            } else {
                0
            }
        };

        // Construct a minimal inner envelope for the recovery notification.
        // Recovery notifications bypass the full send_message pipeline but
        // still go through the envelope crypto layer (seal).
        let timestamp = self.clock.now_millis();
        let params = scp_protocol::envelope::inner::InnerEnvelopeParams {
            version: scp_protocol::envelope::SCP_PROTOCOL_VERSION,
            context_id,
            sender_did,
            epoch: current_epoch,
            generation: 0,
            sequence,
            timestamp,
            message_type: scp_protocol::envelope::inner::MessageType::Recovery,
            payload,
            provenance: None,
            signing_key_id: scp_protocol::identity::SigningKeyId::Active,
        };

        let inner = crate::envelope::inner::sign::create_inner_envelope_raw(&params, signing_key)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // Use domain-separated routing ID for relay routing, distinct from
        // the raw context_id_bytes used for MLS crypto keying.
        let routing_id = scp_protocol::context::context_routing_id(context_id);
        let encrypted = self.crypto.seal(
            &context_id_bytes,
            &inner,
            &routing_id,
            300, // 5 minute blob TTL
        )?;

        // Send via transport using the domain-separated routing ID.
        self.transport.send_message(&routing_id, &encrypted)?;

        Ok(())
    }

    /// Sends a recovery notification to a contact DID by finding shared
    /// contexts where both the recovering DID and the contact are members,
    /// then sending the notification through the first matching context.
    ///
    /// This is the correct entry point for step 5 contact notification (§9.12),
    /// as opposed to `recovery_send_notification` which requires a known
    /// `context_id`. Here the manager searches its registered contexts to find
    /// an appropriate channel.
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
        // Find a context where both the recovering DID and the contact DID
        // are members. The first matching context is used for delivery.
        // Collect (key, Arc) pairs first to release DashMap shard locks before
        // awaiting per-context Mutexes. Holding a DashMap Ref across .await
        // would deadlock any concurrent shard access.
        let shared_context_id = {
            let entries: Vec<(String, Arc<Mutex<PerContextState>>)> = self
                .contexts
                .iter()
                .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
                .collect();
            let mut found = None;
            for (context_id, arc) in entries {
                let ctx = arc.lock().await;
                if ctx.membership.contains(recovering_did) && ctx.membership.contains(contact_did) {
                    found = Some(context_id);
                    break;
                }
            }
            found
        };

        match shared_context_id {
            Some(context_id) => {
                // Contact notifications use sequence=4 (step 5 in recovery).
                self.recovery_send_notification(
                    &context_id,
                    recovering_did,
                    payload,
                    4,
                    signing_key,
                )
                .await
            }
            None => Err(ContextError::TransportFailed(format!(
                "no shared context found between {recovering_did} and {contact_did}"
            ))),
        }
    }
}
