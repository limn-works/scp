//! Message send and receive operations.

use super::{
    Capability, ContextError, ContextEvent, ContextHandle, ContextManager, DID,
    context_id_to_bytes, instrument, require_active,
};

#[allow(clippy::significant_drop_tightening)]
impl ContextManager {
    /// Sends a message within a context.
    ///
    /// For encrypted contexts: validates the context is `Active`, validates the
    /// sender's UCAN for `messages:write` capability, assigns a per-sender
    /// monotonic SCP sequence number, encrypts the message (sender key + MLS +
    /// envelopes), sends via transport, and appends a `MessageSent` event.
    ///
    /// For broadcast contexts: validates `Active` state, checks `can_write`
    /// via `BroadcastContext::publish`, assigns sequence number, and sends
    /// the broadcast envelope via transport.
    ///
    /// See ADR-008 acceptance criterion 8.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if:
    /// - The context is not in `Active` state.
    /// - The sender lacks `messages:write` capability.
    #[instrument(skip_all, fields(context_id = handle.context_id()))]
    pub async fn send_message(
        &self,
        handle: &ContextHandle,
        sender_did: &DID,
        payload: &[u8],
        signing_key: Option<&ed25519_dalek::SigningKey>,
    ) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();
        let context_id_bytes = context_id_to_bytes(&context_id);

        // Phase 1 (under lock): State checks, capability check, membership
        // verification, produce broadcast envelope if applicable. Sequence
        // assignment is deferred to Phase 3 so transport failures don't burn
        // sequence numbers. Do NOT push to receive_buffer yet — transport may
        // fail. See #1420 (phantom events) and #1422 (AAD zeros).
        //
        // NOTE: For the broadcast path, `BroadcastContext::publish()` internally
        // increments the broadcast-level per-author sequence (part of the wire
        // format, AAD, and signature). That sequence burn is unavoidable — it's
        // committed to the envelope before transport. The membership-level
        // sequence (used in the `MessageSent` event) is separate and IS deferred.
        let broadcast_envelope = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(&context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.clone()))?;

            // State check inside lock -- eliminates TOCTOU race.
            require_active(&ctx.handle)?;

            // Governance-level write revocation check (§9.17, ADR-038).
            if ctx.access.write_revoked_members.contains(sender_did) {
                return Err(ContextError::PermissionDenied(format!(
                    "write access has been revoked for {sender_did}"
                )));
            }

            if let Some(ref mut bc) = ctx.broadcast_context {
                // Broadcast path: capability check + seal under lock.
                let sk = signing_key.ok_or_else(|| {
                    ContextError::CryptoFailed(
                        "signing key required for broadcast publish".to_owned(),
                    )
                })?;
                let timestamp = self.clock.now_millis();

                // Compute signing payload and sign externally, matching the
                // pattern used by publish_broadcast (custody-based signing).
                let meta = bc.publish_metadata(sender_did)?;
                let nonce = scp_protocol::crypto::sender_keys::generate_broadcast_nonce();
                let provenance_hash =
                    scp_protocol::crypto::sender_keys::compute_provenance_hash(None)
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
                let signature = ed25519_dalek::Signer::sign(sk, &signing_payload);

                let envelope =
                    bc.publish(sender_did, payload, timestamp, signature, &nonce, None)?;

                Some(envelope)
            } else {
                // Encrypted path: role-based capability check under lock.
                if !ctx
                    .role_state
                    .member_has_capability(sender_did, &Capability::MessagesWrite)
                {
                    return Err(ContextError::PermissionDenied(format!(
                        "member {sender_did} does not have messages:write capability"
                    )));
                }

                None
            }
        };
        // Lock dropped before crypto/transport/event-log calls.

        // Phase 2 (no lock): Encrypt + send via transport.
        // If either fails, return error — no phantom MessageSent in buffer.
        // Sequence number is burned on failure (gaps are harmless).
        let encrypted = if let Some(envelope) = broadcast_envelope {
            // Broadcast: serialize the full BroadcastEnvelope for transport.
            // The relay stores the entire envelope so that the node's projection
            // layer can reconstruct metadata without decrypting.
            rmp_serde::to_vec_named(&envelope)
                .map_err(|e| ContextError::CryptoFailed(format!("envelope serialization: {e}")))?
        } else {
            // Encrypted: sender key (ADR-007) -> inner envelope (ADR-002) ->
            // MLS (ADR-001) -> outer envelope.
            // Epoch 0 for standard sender keys (epoch tracking is per-sender-key,
            // incremented on key rotation). Sequence 0 — changing this requires
            // sending the sequence in the clear alongside the ciphertext so the
            // receiver can reconstruct the AAD.
            let encrypt_start = std::time::Instant::now();
            let result =
                self.crypto
                    .encrypt_message(&context_id_bytes, sender_did, payload, 0, 0)?;
            crate::metrics::record_encrypt_duration(encrypt_start.elapsed());
            result
        };

        // Send via transport.
        self.transport.send_message(&context_id_bytes, &encrypted)?;

        // Record message sent metric (#1467).
        crate::metrics::record_message_sent();

        // Phase 3 (re-acquire lock): Re-check context active + membership,
        // assign sequence number NOW (post-transport), then push MessageSent
        // event to receive buffer. Only reached on successful transport send —
        // no phantom events (#1420), no burned sequence numbers.
        {
            let mut contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get_mut(&context_id) {
                // Best-effort: if context was closed/left during transport send,
                // skip the event push. The message was still sent on the wire,
                // but the local context is no longer active.
                if require_active(&ctx.handle).is_ok() {
                    let seq = ctx.membership.next_sequence_number(sender_did).unwrap_or(0);
                    ctx.receive_buffer.push(ContextEvent::MessageSent {
                        sender_did: sender_did.clone(),
                        sequence_number: seq,
                        payload: payload.to_vec(),
                    });
                }
            }
        }

        // Append MessageSent event to event log.
        self.event_log
            .append_context_event(&context_id_bytes, "MessageSent")?;

        // Persist context state after send (best-effort).
        // Guarded: skip mutex re-acquisition and deep-clone when no
        // persistence provider is configured (the common case for bridges).
        if self.has_persistence() {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(&context_id) {
                let snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(&context_id, snapshot);
            }
        }

        Ok(())
    }

    /// Delivers an incoming encrypted message from the relay to a context.
    ///
    /// Decrypts the ciphertext using the crypto provider (MLS + sender key),
    /// validates the context is `Active`, and emits a `MessageReceived` event
    /// to the context's receive buffer.
    ///
    /// Returns `(plaintext, sender_did)` on success so the FFI bridge can
    /// forward the decrypted message to the SDK consumer.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if:
    /// - The context is not registered or not in `Active` state.
    /// - Decryption fails (MLS or sender key layer).
    #[instrument(skip_all, fields(context_id))]
    pub async fn deliver_incoming(
        &self,
        context_id: &str,
        encrypted_blob: &[u8],
    ) -> Result<Option<(Vec<u8>, String)>, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        // Phase 1: Acquire lock → state check → drop lock.
        // Follows the send_message pattern: narrow lock scope so decrypt
        // (which is sync but potentially expensive) doesn't serialize all
        // context operations behind a single global mutex.
        {
            let contexts = self.contexts.lock().await;
            let ctx = contexts
                .get(context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            require_active(&ctx.handle)?;
        }

        // Phase 2: Decrypt outside the lock.
        // `decrypt_message` is sync and takes its own internal mutex for
        // OpenMLS group state — no need to hold `self.contexts` here.
        // MLS layer (ADR-001) -> sender key layer (ADR-007).
        //
        // AAD epoch=0, sequence=0: The sender key AAD includes epoch and
        // sequence for replay/reorder protection (spec §9.7). However, the
        // current wire format does not transmit these values in the clear —
        // they are encrypted inside the MLS ciphertext. The receiver therefore
        // cannot reconstruct the sender's epoch/sequence without first
        // decrypting, creating a chicken-and-egg problem. Both send and
        // receive paths use hardcoded zeros until the wire format carries
        // epoch/sequence in an authenticated-but-unencrypted header (see
        // #1422). This is safe because MLS already provides its own replay
        // protection via the ratchet tree; the sender key AAD is a
        // defense-in-depth layer that is currently inert.
        let decrypt_start = std::time::Instant::now();
        let decrypted = self
            .crypto
            .decrypt_message(&context_id_bytes, encrypted_blob, 0, 0)?;
        crate::metrics::record_decrypt_duration(decrypt_start.elapsed());

        // Commit/Proposal messages have no application payload — the MLS epoch
        // was advanced (Commit) or the proposal was cached (Proposal). Skip
        // membership checks and buffer push.
        let Some((plaintext, sender_did)) = decrypted else {
            return Ok(None);
        };

        // Phase 3: Re-acquire lock → re-check active → verify membership →
        // capability check → push to receive buffer. Re-checking eliminates the
        // TOCTOU window between Phase 1 and Phase 3.
        let sender_did_obj = DID(sender_did.clone());
        {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;

            // Re-check active state: context may have been closed/left during decrypt.
            require_active(&ctx.handle)?;

            // Verify sender is a current member and not write-revoked (§9.17,
            // ADR-038). Mirrors the send_message path's membership checks.
            if !ctx.membership.contains(&sender_did) {
                return Err(ContextError::MemberNotFound(format!(
                    "sender {sender_did} is not a member of this context"
                )));
            }
            if ctx.access.write_revoked_members.contains(&sender_did_obj) {
                return Err(ContextError::PermissionDenied(format!(
                    "write access has been revoked for {sender_did}"
                )));
            }

            // Role-based capability check, mirroring send_message's encrypted path.
            if !ctx
                .role_state
                .member_has_capability(&sender_did, &Capability::MessagesWrite)
            {
                return Err(ContextError::PermissionDenied(format!(
                    "member {sender_did} does not have messages:write capability"
                )));
            }

            // Emit MessageReceived event to the receive buffer.
            ctx.receive_buffer.push(ContextEvent::MessageReceived {
                sender_did: sender_did_obj,
                payload: plaintext.clone(),
            });
        }

        // Record message received metric (#1467).
        crate::metrics::record_message_received();

        // Append event to event log (best-effort, matches send_message).
        let _ = self
            .event_log
            .append_context_event(&context_id_bytes, "MessageReceived");

        Ok(Some((plaintext, sender_did)))
    }
}
