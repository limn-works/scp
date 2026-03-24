//! Broadcast context operations (subscribe, publish, block).

use super::{
    BlockResult, BroadcastAdmission, BroadcastContent, BroadcastContext, BroadcastEnvelope,
    BuildHasher, ContextError, ContextEvent, ContextManager, DID, DidResolver, KeyRequestDecision,
    NonceTracker, ProofResolver, RevocationChecker, SubscriptionResult, UcanToken,
    UnsubscribeResult, ValidationContext, context_id_to_bytes, instrument, require_active,
    serialize_broadcast_content,
};

#[allow(clippy::significant_drop_tightening)]
impl ContextManager {
    /// Subscribes a DID to a broadcast context.
    ///
    /// For open broadcast contexts, any DID can subscribe without a UCAN.
    /// For gated contexts, a valid `messagesRead` UCAN is required and
    /// validated through the full 11-step pipeline (ADR-016).
    ///
    /// Returns the current author key epochs so the subscriber knows which
    /// epochs to request keys for.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not a broadcast
    ///   context or the subscriber is already registered.
    /// - [`ContextError::PermissionDenied`] if the context is gated and no
    #[instrument(skip_all, fields(context_id))]
    pub async fn subscribe_broadcast<D, N, R, P, S>(
        &self,
        context_id: &str,
        subscriber_did: &DID,
        ucan: Option<&UcanToken>,
        timestamp: u64,
        validation_ctx: Option<&mut ValidationContext<'_, D, N, R, P, S>>,
    ) -> Result<SubscriptionResult, ContextError>
    where
        D: DidResolver + Send + Sync,
        N: NonceTracker + Send + Sync,
        R: RevocationChecker + Send + Sync,
        P: ProofResolver + Send + Sync,
        S: BuildHasher + Send + Sync,
    {
        let context_id_bytes = context_id_to_bytes(context_id);

        let (result, snapshot) = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;

            require_active(&ctx.handle)?;

            // Version compatibility check (spec §13.4): reject subscribe if the
            // context requires a protocol version higher than this SDK supports.
            // Applies to ALL context modes including broadcast.
            ctx.handle
                .params()
                .check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;

            let bc = ctx
                .broadcast_context
                .as_mut()
                .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

            let result = bc.subscribe(subscriber_did, ucan, timestamp, validation_ctx)?;

            // Take snapshot for persistence before dropping lock (skip if
            // no persistence provider is configured).
            let snapshot = if self.has_persistence() {
                Some(bc.to_snapshot())
            } else {
                None
            };

            // Add subscriber to membership tracking (role = "subscriber").
            ctx.membership
                .add_member(subscriber_did.clone(), "subscriber".into(), vec![]);

            // Push event to receive buffer.
            ctx.receive_buffer.push(result.event.clone());

            (result, snapshot)
        };
        // Lock dropped.

        // Persist broadcast state for crash recovery.
        if let Some(ref snapshot) = snapshot {
            self.persist_broadcast_snapshot(context_id, snapshot);
        }

        // Persist context state after subscribe (best-effort).
        if self.has_persistence() {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(context_id) {
                let ctx_snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(context_id, ctx_snapshot);
            }
        }

        // Append event to persistent event log.
        self.event_log
            .append_context_event(&context_id_bytes, "MemberJoined")?;

        Ok(result)
    }

    /// Unsubscribes a DID from a broadcast context.
    ///
    /// When `rotate_keys` is `true`, all authors rotate their broadcast keys
    /// to ensure forward secrecy (the departed subscriber cannot decrypt
    /// future content).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not a broadcast
    ///   context.
    #[instrument(skip_all, fields(context_id))]
    pub async fn unsubscribe_broadcast(
        &self,
        context_id: &str,
        subscriber_did: &DID,
        rotate_keys: bool,
    ) -> Result<UnsubscribeResult, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let (result, snapshot) = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;

            require_active(&ctx.handle)?;

            let bc = ctx
                .broadcast_context
                .as_mut()
                .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

            let result = bc.unsubscribe(subscriber_did, rotate_keys)?;

            // Take snapshot for persistence before dropping lock (skip if
            // no persistence provider is configured).
            let snapshot = if self.has_persistence() {
                Some(bc.to_snapshot())
            } else {
                None
            };

            // Remove from membership tracking.
            ctx.membership.remove_member(subscriber_did);

            // Emit MemberLeft event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::MemberLeft {
                member_did: subscriber_did.clone(),
            });

            (result, snapshot)
        };
        // Lock dropped.

        // Persist broadcast state for crash recovery.
        if let Some(ref snapshot) = snapshot {
            self.persist_broadcast_snapshot(context_id, snapshot);
        }

        // Persist context state after unsubscribe (best-effort).
        if self.has_persistence() {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(context_id) {
                let ctx_snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(context_id, ctx_snapshot);
            }
        }

        self.event_log
            .append_context_event(&context_id_bytes, "MemberLeft")?;

        Ok(result)
    }

    /// Publishes a message to a broadcast context.
    ///
    /// Validates that the sender is a registered author (`messagesWrite`),
    /// seals the payload with the author's broadcast key, assigns a sequence
    /// number, and sends via transport.
    ///
    /// This is the broadcast-specific publish path. For a unified API, use
    /// [`send_message`](Self::send_message) which routes to this path
    /// automatically for broadcast contexts.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not broadcast.
    /// - [`ContextError::PermissionDenied`] if the sender is not an author.
    #[instrument(skip_all, fields(context_id))]
    pub async fn publish_broadcast(
        &self,
        context_id: &str,
        author_did: &DID,
        payload: &[u8],
        custody: &impl scp_platform::KeyCustody,
        signing_key_handle: &scp_platform::KeyHandle,
    ) -> Result<BroadcastEnvelope, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let envelope = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;

            require_active(&ctx.handle)?;

            // Governance-level write revocation check (§9.17, ADR-038).
            if ctx.access.write_revoked_members.contains(author_did) {
                return Err(ContextError::PermissionDenied(format!(
                    "write access has been revoked for {author_did}"
                )));
            }

            let bc = ctx
                .broadcast_context
                .as_mut()
                .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

            let timestamp = self.clock.now_millis();

            // Compute the signing payload externally so we can sign via
            // key custody (async) while keeping seal_broadcast synchronous.
            let meta = bc.publish_metadata(author_did)?;
            let nonce = scp_protocol::crypto::sender_keys::generate_broadcast_nonce();
            let provenance_hash = scp_protocol::crypto::sender_keys::compute_provenance_hash(None)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
            let signing_payload =
                scp_protocol::crypto::sender_keys::build_broadcast_signing_payload(
                    &scp_protocol::crypto::sender_keys::SigningPayloadFields {
                        version: scp_protocol::envelope::SCP_PROTOCOL_VERSION,
                        context_id: meta.context_id,
                        author_did: meta.author_did,
                        sequence: meta.next_sequence,
                        key_epoch: meta.key_epoch,
                        timestamp,
                        nonce: &nonce,
                        provenance_hash: &provenance_hash,
                    },
                );

            // Sign via key custody (async).
            let platform_sig = custody
                .sign(signing_key_handle, &signing_payload)
                .await
                .map_err(|e| ContextError::CryptoFailed(format!("custody signing failed: {e}")))?;
            let sig_bytes: [u8; 64] = platform_sig.as_bytes().try_into().map_err(|_| {
                ContextError::CryptoFailed(format!(
                    "custody signature has wrong length: expected 64, got {}",
                    platform_sig.as_bytes().len()
                ))
            })?;
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

            let envelope = bc.publish(author_did, payload, timestamp, signature, &nonce, None)?;

            // Assign per-sender monotonic sequence number.
            let seq = ctx
                .membership
                .next_sequence_number(author_did)
                .ok_or_else(|| ContextError::MemberNotFound(author_did.to_string()))?;

            ctx.receive_buffer.push(ContextEvent::MessageSent {
                sender_did: author_did.clone(),
                sequence_number: seq,
                payload: payload.to_vec(),
            });

            envelope
        };
        // Lock dropped.

        // Serialize the full BroadcastEnvelope for transport. The relay stores
        // the entire envelope (not just encrypted_content) so that the node's
        // projection layer can reconstruct metadata (author_did, key_epoch, etc.)
        // without decrypting.
        let envelope_bytes = rmp_serde::to_vec_named(&envelope)
            .map_err(|e| ContextError::CryptoFailed(format!("envelope serialization: {e}")))?;

        // Send via transport.
        self.transport
            .send_message(&context_id_bytes, &envelope_bytes)?;

        // Append event to persistent event log.
        self.event_log
            .append_context_event(&context_id_bytes, "MessageSent")?;

        Ok(envelope)
    }

    /// Publishes a [`BroadcastContent`] to a broadcast context.
    ///
    /// This is the structured-content publish path. It serializes the
    /// `BroadcastContent` with the magic prefix and delegates to
    /// [`publish_broadcast`](Self::publish_broadcast).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not broadcast.
    /// - [`ContextError::PermissionDenied`] if the sender is not an author.
    /// - `ContextError::InvalidInput` if serialization fails.
    #[instrument(skip_all, fields(context_id))]
    pub async fn publish_broadcast_content(
        &self,
        context_id: &str,
        author_did: &DID,
        content: BroadcastContent,
        custody: &impl scp_platform::KeyCustody,
        signing_key_handle: &scp_platform::KeyHandle,
    ) -> Result<BroadcastEnvelope, ContextError> {
        let payload = serialize_broadcast_content(&content).map_err(|e| {
            ContextError::CryptoFailed(format!("content serialization failed: {e}"))
        })?;
        self.publish_broadcast(
            context_id,
            author_did,
            &payload,
            custody,
            signing_key_handle,
        )
        .await
    }

    /// Blocks a subscriber from receiving future broadcast keys from a
    /// specific author.
    ///
    /// The author's broadcast key is rotated and the subscriber is added to
    /// the author's block list. The blocked subscriber receives no response
    /// to future key requests and cannot decrypt content encrypted with the
    /// new key.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not broadcast.
    /// - [`ContextError::MemberNotFound`] if the author is not registered.
    #[instrument(skip_all, fields(context_id))]
    pub async fn block_broadcast_subscriber(
        &self,
        context_id: &str,
        author_did: &DID,
        subscriber_did: &DID,
    ) -> Result<BlockResult, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let (result, snapshot) = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;

            require_active(&ctx.handle)?;

            let bc = ctx
                .broadcast_context
                .as_mut()
                .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

            let result = bc.block_subscriber(author_did, subscriber_did)?;

            // Take snapshot for persistence before dropping lock (skip if
            // no persistence provider is configured).
            let snapshot = if self.has_persistence() {
                Some(bc.to_snapshot())
            } else {
                None
            };

            // Emit block event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::MemberBlocked {
                blocked_did: subscriber_did.clone(),
                author_did: author_did.clone(),
            });

            (result, snapshot)
        };
        // Lock dropped.

        // Persist broadcast state for crash recovery.
        if let Some(ref snapshot) = snapshot {
            self.persist_broadcast_snapshot(context_id, snapshot);
        }

        self.event_log
            .append_context_event(&context_id_bytes, "MemberBlocked")?;

        Ok(result)
    }

    /// Unblocks a previously blocked subscriber in a broadcast context
    /// (§9.16.8 — forward-only restoration).
    ///
    /// Removes the subscriber DID from the specified author's block list.
    /// Per §9.16.8, the author does NOT rotate their sender key. The
    /// unblocked subscriber can request the current key on next pull but
    /// cannot decrypt content from the block period.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered
    ///   or is not a broadcast context.
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MemberNotFound`] if the author DID is not registered.
    /// - [`ContextError::InvalidState`] if the subscriber is not blocked.
    #[instrument(skip_all, fields(context_id))]
    pub async fn unblock_broadcast_subscriber(
        &self,
        context_id: &str,
        author_did: &DID,
        subscriber_did: &DID,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;

            require_active(&ctx.handle)?;

            let bc = ctx
                .broadcast_context
                .as_mut()
                .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

            let _result = bc.unblock_subscriber(author_did, subscriber_did)?;

            // Take snapshot for persistence before dropping lock.
            let snapshot = if self.has_persistence() {
                Some(bc.to_snapshot())
            } else {
                None
            };

            // Emit unblock event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::MemberUnblocked {
                unblocked_did: subscriber_did.clone(),
                author_did: author_did.clone(),
            });

            snapshot
        };
        // Lock dropped.

        // Persist broadcast state for crash recovery.
        if let Some(ref snapshot) = snapshot {
            self.persist_broadcast_snapshot(context_id, snapshot);
        }

        self.event_log
            .append_context_event(&context_id_bytes, "MemberUnblocked")?;

        Ok(())
    }

    /// Evaluates whether a subscriber's broadcast key request should be
    /// granted or denied.
    ///
    /// This is the author-side decision function for the pull-based key
    /// distribution protocol (spec section 9.16.6).
    ///
    /// # Defense-in-depth validation (#234)
    ///
    /// Before delegating to `BroadcastContext::handle_key_request`, this
    /// method verifies that `author_did` is registered as a locally
    /// controlled DID via [`register_local_did`](Self::register_local_did).
    /// This prevents misuse if the method is called from an unexpected
    /// context. Transport-layer auth (spec section 9.16.6) remains the
    /// primary enforcement mechanism; this check is an additional layer.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::PermissionDenied`] if `author_did` is not
    /// registered as a locally controlled DID.
    ///
    /// Returns [`ContextError::MembershipFailed`] if the context is not
    #[instrument(skip_all, fields(context_id))]
    pub async fn handle_broadcast_key_request(
        &self,
        context_id: &str,
        author_did: &DID,
        requester_did: &DID,
    ) -> Result<KeyRequestDecision, ContextError> {
        // Defense-in-depth: verify the local SDK controls the author DID.
        // Transport-layer auth (section 9.16.6) is the primary gate; this prevents
        // misuse if the method is ever called from a different context.
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

        Ok(bc.handle_key_request(author_did, requester_did))
    }

    /// Returns the number of subscribers in a broadcast context.
    ///
    /// Returns `None` if the context is not registered or not broadcast.
    #[instrument(skip_all, fields(context_id))]
    pub async fn broadcast_subscriber_count(&self, context_id: &str) -> Option<usize> {
        self.contexts.lock().await.get(context_id).and_then(|ctx| {
            ctx.broadcast_context
                .as_ref()
                .map(BroadcastContext::subscriber_count)
        })
    }

    /// Returns `true` if the given DID is a subscriber in a broadcast context.
    #[instrument(skip_all, fields(context_id))]
    pub async fn is_broadcast_subscriber(&self, context_id: &str, did: &str) -> bool {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .and_then(|ctx| {
                ctx.broadcast_context
                    .as_ref()
                    .map(|bc| bc.is_subscriber(did))
            })
            .unwrap_or(false)
    }

    /// Returns the admission policy for a broadcast context.
    ///
    /// Returns `None` if the context is not registered or not broadcast.
    #[instrument(skip_all, fields(context_id))]
    pub async fn broadcast_admission(&self, context_id: &str) -> Option<BroadcastAdmission> {
        self.contexts.lock().await.get(context_id).and_then(|ctx| {
            ctx.broadcast_context
                .as_ref()
                .map(BroadcastContext::admission)
        })
    }
}
