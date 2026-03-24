//! Message send and receive operations.

use sha2::Digest;
use subtle::ConstantTimeEq;

use scp_protocol::crypto::access_keys::wrapping::Recipient;
use scp_protocol::envelope::inner::{InnerEnvelopeParams, MessageType};
use scp_protocol::envelope::validation::{BufferedMessage, SequenceCheck, TimestampValidator};
use scp_protocol::identity::SigningKeyId;

use super::{
    Capability, ContextError, ContextEvent, ContextHandle, ContextManager, DID,
    context_id_to_bytes, instrument, require_active,
};

/// Re-export of the protocol-level domain-separated routing ID derivation.
///
/// Uses `SHA-256("scp:context-routing:" || context_id)` to produce a
/// 32-byte routing ID distinct from the raw `context_id_bytes` (which is
/// `SHA-256(context_id)` without domain separation).
///
/// Both the send path and subscribe path MUST use this function so that
/// the relay routes messages to the correct subscribers.
pub(super) fn derive_routing_id(context_id: &str) -> [u8; 32] {
    scp_protocol::context::context_routing_id(context_id)
}

/// Builds a broadcast envelope for the send path.
///
/// Handles signing payload construction, signature generation, and
/// `BroadcastContext::publish`.
fn build_broadcast_envelope(
    clock: &dyn scp_primitives::Clock,
    bc: &mut scp_protocol::context::broadcast::BroadcastContext,
    sender_did: &DID,
    payload: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<scp_protocol::crypto::sender_keys::broadcast::BroadcastEnvelope, ContextError> {
    let timestamp = clock.now_millis();
    let meta = bc.publish_metadata(sender_did)?;
    let nonce = scp_protocol::crypto::sender_keys::generate_broadcast_nonce();
    let provenance_hash = scp_protocol::crypto::sender_keys::compute_provenance_hash(None)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
    let signing_payload = scp_protocol::crypto::sender_keys::build_broadcast_signing_payload(
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
    let signature = ed25519_dalek::Signer::sign(signing_key, &signing_payload);
    bc.publish(sender_did, payload, timestamp, signature, &nonce, None)
}

/// Default blob TTL for outer envelopes (5 minutes / 300 seconds).
/// Relays may store the blob up to this duration for offline recipients.
const DEFAULT_BLOB_TTL_SECS: u32 = 300;

/// Builds the encrypted envelope bytes for the send path.
///
/// Handles: access key wrapping, inner envelope creation (sign + pad),
/// and sealing (sender key + MLS + outer envelope).
#[allow(clippy::too_many_arguments)]
fn build_encrypted_envelope(
    manager: &ContextManager,
    context_id: &str,
    sender_did: &DID,
    payload: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
    recipients_data: &std::collections::HashMap<
        String,
        scp_protocol::crypto::access_keys::AccessKey,
    >,
    sequence: u64,
    source_provenance: Option<&scp_protocol::provenance::attach::SourceContextInfo>,
) -> Result<Vec<u8>, ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);
    // Provenance: attach when cross-context data is present.
    // For intra-context messages (the normal case), no cross-context source
    // exists and provenance is None. The InnerEnvelope signature covers the
    // provenance hash regardless (SHA-256(0x00) for absent provenance).
    let provenance = source_provenance.map(|source_info| {
        let target_context: scp_protocol::provenance::ContextId = context_id.to_owned();
        let dp = scp_protocol::provenance::attach::attach_provenance(
            source_info,
            &target_context,
            None, // no existing chain
            None, // no pseudonym key for intra-context
            None, // no payment info
        );
        scp_protocol::envelope::inner::Provenance {
            source: dp.source_context,
            upstream_hash: None,
        }
    });

    // Access key wrapping: wrap content for all members.
    // Note: The access key layer uses the original `context_id` string as AAD
    // (protocol-level addressing), while the sender key layer (in seal())
    // uses `hex::encode(context_id_bytes)` as AAD (crypto-level addressing).
    // This is intentional: access keys are protocol-level constructs bound to
    // the human-readable context ID, while sender keys operate on the hashed
    // context ID used for MLS group identification and routing.
    let recipients: Vec<Recipient<'_>> = recipients_data
        .iter()
        .map(|(did, key)| Recipient {
            did: did.as_str(),
            access_key: key,
        })
        .collect();

    let wrapped = scp_protocol::crypto::access_keys::wrapping::wrap_content(
        payload,
        &recipients,
        context_id,
        sender_did.as_ref(),
        0,
        0,
    )
    .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    let wrapped_bytes = rmp_serde::to_vec_named(&wrapped)
        .map_err(|e| ContextError::CryptoFailed(format!("wrapped content serialization: {e}")))?;

    // Create inner envelope (sign + pad).
    let timestamp = manager.clock.now_millis();
    let params = InnerEnvelopeParams {
        version: scp_protocol::envelope::SCP_PROTOCOL_VERSION,
        context_id,
        sender_did: sender_did.as_ref(),
        epoch: 0,
        generation: 0,
        sequence,
        timestamp,
        message_type: MessageType::Content,
        payload: &wrapped_bytes,
        provenance,
        signing_key_id: SigningKeyId::Active,
    };

    let inner = crate::envelope::inner::sign::create_inner_envelope_raw(&params, signing_key)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    // Seal: sender key + MLS + outer envelope.
    // Routing ID uses domain-separated derivation per ADR-002, not raw
    // context_id_bytes, to prevent routing IDs from colliding with other
    // SHA-256(context_id) usages (MLS groups, event logs).
    let routing_id = derive_routing_id(context_id);
    manager.crypto.seal(
        &context_id_bytes,
        &inner,
        &routing_id,
        DEFAULT_BLOB_TTL_SECS,
    )
}

/// Verifies signature and unwraps access keys from a received inner envelope.
///
/// Call after `crypto.open` returns `Some(OpenedEnvelope)` and BEFORE
/// anti-replay validation (to prevent tracker poisoning by forged envelopes).
/// Returns the original plaintext.
///
/// `sender_is_admin` gates Recovery-type messages: only admins may send
/// Recovery messages (which bypass access key wrapping). Without this
/// check, any member could set `message_type = Recovery` to evade the
/// access key layer.
fn verify_and_unwrap(
    manager: &ContextManager,
    inner: &scp_protocol::envelope::inner::InnerEnvelope,
    sender_did: &str,
    context_id: &str,
    local_member_did: &str,
    access_key: &scp_protocol::crypto::access_keys::AccessKey,
    sender_is_admin: bool,
) -> Result<Vec<u8>, ContextError> {
    // Verify inner signature (fail-closed: reject if key cannot be resolved).
    let public_key = (manager.key_resolver)(&DID(sender_did.to_owned())).ok_or_else(|| {
        ContextError::CryptoFailed(format!("cannot resolve public key for sender {sender_did}"))
    })?;
    let valid = scp_protocol::envelope::inner::verify_inner_signature(inner, public_key.as_bytes())
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
    if !valid {
        return Err(ContextError::CryptoFailed(
            "inner envelope signature verification failed".into(),
        ));
    }

    // Strip padding to recover wrapped content and verify content integrity.
    // The inner envelope arrives with its padded payload intact from open();
    // stripping and integrity verification are performed here in one place.
    let stripped = scp_protocol::envelope::padding::strip_padding(&inner.payload)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    // Verify content integrity (constant-time comparison).
    let computed_hash: [u8; 32] = sha2::Sha256::digest(&stripped).into();
    if !bool::from(computed_hash[..].ct_eq(&inner.payload_hash[..])) {
        return Err(ContextError::CryptoFailed(
            "content integrity check failed".into(),
        ));
    }

    // Recovery messages bypass the access key wrapping layer (§9.12).
    // The send path in trust_recovery.rs does not wrap the payload with
    // access keys, so attempting to deserialize as WrappedContent would fail.
    //
    // Defense: only admins (members with ContextClose capability) may send
    // Recovery-type messages. Without this gate, any member could set
    // message_type = Recovery on arbitrary content to bypass access key
    // wrapping entirely.
    if inner.message_type == MessageType::Recovery {
        if !sender_is_admin {
            return Err(ContextError::PermissionDenied(
                "only admins can send Recovery-type messages".into(),
            ));
        }
        return Ok(stripped);
    }

    // Deserialize and unwrap access key layer.
    let wrapped: scp_protocol::crypto::access_keys::WrappedContent =
        rmp_serde::from_slice(&stripped)
            .map_err(|e| ContextError::CryptoFailed(format!("wrapped content: {e}")))?;

    scp_protocol::crypto::access_keys::wrapping::unwrap_content(
        &wrapped,
        local_member_did,
        access_key,
        context_id,
        sender_did,
        0,
        0,
    )
    .map_err(|e| ContextError::CryptoFailed(e.to_string()))
}

#[allow(clippy::significant_drop_tightening)]
impl ContextManager {
    /// Sends a message within a context.
    ///
    /// For encrypted contexts: constructs a signed inner envelope with access
    /// key wrapping, seals through the full envelope pipeline, sends via
    /// transport, and appends a `MessageSent` event.
    ///
    /// For broadcast contexts: validates `Active` state, checks `can_write`
    /// via `BroadcastContext::publish`, assigns sequence number, and sends
    /// the broadcast envelope via transport.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the context is not active, the sender
    /// lacks capability, or any crypto/transport step fails.
    #[instrument(skip_all, fields(context_id = handle.context_id()))]
    pub async fn send_message(
        &self,
        handle: &ContextHandle,
        sender_did: &DID,
        payload: &[u8],
        signing_key: Option<&ed25519_dalek::SigningKey>,
        source_provenance: Option<&scp_protocol::provenance::attach::SourceContextInfo>,
    ) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();
        let context_id_bytes = context_id_to_bytes(&context_id);
        let routing_id = scp_protocol::context::context_routing_id(&context_id);
        let (broadcast_envelope, recipients_data, sequence, is_broadcast) = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(&context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.clone()))?;
            require_active(&ctx.handle)?;
            if ctx.access.write_revoked_members.contains(sender_did) {
                return Err(ContextError::PermissionDenied(format!(
                    "write access has been revoked for {sender_did}"
                )));
            }
            if let Some(ref mut bc) = ctx.broadcast_context {
                let sk = signing_key.ok_or_else(|| {
                    ContextError::CryptoFailed("signing key required for broadcast publish".into())
                })?;
                let envelope =
                    build_broadcast_envelope(self.clock.as_ref(), bc, sender_did, payload, sk)?;
                (Some(envelope), std::collections::HashMap::new(), 0, true)
            } else {
                if !ctx
                    .role_state
                    .member_has_capability(sender_did, &Capability::MessagesWrite)
                {
                    return Err(ContextError::PermissionDenied(format!(
                        "member {sender_did} does not have messages:write capability"
                    )));
                }
                // Assign sequence number under the lock (Phase 1) so the inner
                // envelope carries the real sequence. SequenceTracker on the
                // receive side rejects duplicates, so this must be consumed once.
                let seq = ctx
                    .membership
                    .next_sequence_number(sender_did)
                    .ok_or_else(|| {
                        ContextError::MemberNotFound(format!(
                            "cannot assign sequence: {sender_did} is not a member"
                        ))
                    })?;
                (
                    None,
                    ctx.access.access_key_store.get_all(&context_id),
                    seq,
                    false,
                )
            }
        };
        // Phase 2 (no lock): Encrypt + send.
        // If encryption or transport fails, roll back the sequence number
        // consumed in Phase 1 so it is not permanently burned (#1420).
        let phase2_result = (|| -> Result<(), ContextError> {
            let encrypted = if let Some(envelope) = broadcast_envelope {
                rmp_serde::to_vec_named(&envelope).map_err(|e| {
                    ContextError::CryptoFailed(format!("envelope serialization: {e}"))
                })?
            } else {
                let encrypt_start = std::time::Instant::now();
                let sk = signing_key.ok_or_else(|| {
                    ContextError::CryptoFailed("signing key required for encrypted send".into())
                })?;
                let result = build_encrypted_envelope(
                    self,
                    &context_id,
                    sender_did,
                    payload,
                    sk,
                    &recipients_data,
                    sequence,
                    source_provenance,
                )?;
                crate::metrics::record_encrypt_duration(encrypt_start.elapsed());
                result
            };
            self.transport.send_message(&routing_id, &encrypted)?;
            crate::metrics::record_message_sent();
            Ok(())
        })();

        if let Err(e) = phase2_result {
            // Only roll back sequence numbers for the encrypted path —
            // broadcast contexts manage their own sequence numbering via
            // BroadcastContext::publish and do not consume from the
            // membership-level SequenceTracker.
            if !is_broadcast {
                let mut contexts = self.contexts.lock().await;
                if let Some(ctx) = contexts.get_mut(&context_id) {
                    ctx.membership.rollback_sequence_number(sender_did);
                }
            }
            return Err(e);
        }
        // Phase 3: push MessageSent event + persist.
        self.finalize_send(
            &context_id,
            &context_id_bytes,
            sender_did,
            sequence,
            payload,
        )
        .await
    }

    /// Pushes a `MessageSent` event, appends to the event log, and persists.
    ///
    /// Extracted from `send_message` Phase 3 to keep the outer function
    /// within the clippy `too_many_lines` limit.
    async fn finalize_send(
        &self,
        context_id: &str,
        context_id_bytes: &[u8; 32],
        sender_did: &DID,
        sequence: u64,
        payload: &[u8],
    ) -> Result<(), ContextError> {
        {
            let mut contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get_mut(context_id)
                && require_active(&ctx.handle).is_ok()
            {
                ctx.receive_buffer.push(ContextEvent::MessageSent {
                    sender_did: sender_did.clone(),
                    sequence_number: sequence,
                    payload: payload.to_vec(),
                });
            }
        }
        self.event_log
            .append_context_event(context_id_bytes, "MessageSent")?;
        if self.has_persistence() {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(context_id) {
                let snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(context_id, snapshot);
            }
        }
        Ok(())
    }

    /// Delivers an incoming encrypted message from the relay to a context.
    ///
    /// Opens the received envelope through the full receive pipeline,
    /// verifies the inner signature, validates anti-replay sequence numbers,
    /// unwraps content access keys, and emits a `MessageReceived` event.
    ///
    /// Out-of-order messages (§9.8.5) are buffered in a per-sender reorder
    /// buffer (up to 100 messages). When a gap fills, all consecutive buffered
    /// messages are delivered in order. If a gap persists for more than 30
    /// seconds, buffered messages are force-delivered with a suppression alert.
    ///
    /// Returns `Ok(Some((plaintext, sender_did)))` when a message is delivered
    /// immediately, `Ok(None)` when the message is buffered (gap detected) or
    /// was a Commit/Proposal, or `Err` on failure.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the context is not active, decryption
    /// fails, signature verification fails, anti-replay check fails,
    /// access key unwrapping fails, or the sender lacks capability.
    #[instrument(skip_all, fields(context_id))]
    pub async fn deliver_incoming(
        &self,
        context_id: &str,
        encrypted_blob: &[u8],
    ) -> Result<Option<(Vec<u8>, String)>, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        // Phase 1: state check + read local member DID + access key.
        // Read local_dids FIRST (RwLock read, low contention) to avoid
        // nested lock ordering issues with the contexts Mutex.
        let local_dids = self.local_dids.read().await;
        let (local_member_did, access_key) = {
            let contexts = self.contexts.lock().await;
            let ctx = contexts
                .get(context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            require_active(&ctx.handle)?;
            let did = ctx
                .membership
                .member_dids()
                .find(|d| local_dids.contains(*d))
                .map(std::string::ToString::to_string)
                .ok_or_else(|| {
                    ContextError::CryptoFailed("no local member found in this context".into())
                })?;
            let key = ctx.access.access_key_store.get(context_id, &did).cloned();
            (did, key)
        };
        drop(local_dids);

        // Phase 2: open envelope (MLS + sender key + deserialize + integrity).
        let decrypt_start = std::time::Instant::now();
        let opened = self.crypto.open(&context_id_bytes, encrypted_blob)?;
        crate::metrics::record_decrypt_duration(decrypt_start.elapsed());

        let Some(opened_envelope) = opened else {
            return Ok(None);
        };

        let inner = opened_envelope.inner;
        let sender_did = opened_envelope.sender_did;

        // Cross-context injection defense: verify that the inner envelope's
        // context_id matches the context we are delivering into. An attacker
        // could try to deliver an envelope from context A into context B's
        // receive path — this check prevents that.
        if inner.context_id != context_id {
            return Err(ContextError::CryptoFailed(format!(
                "inner envelope context_id mismatch: expected {context_id}, got {}",
                inner.context_id
            )));
        }

        // Verify that the sender DID extracted from MLS credentials matches the
        // sender DID declared in the inner envelope. A mismatch indicates a
        // credential spoofing attack.
        if inner.sender_did != sender_did {
            return Err(ContextError::CryptoFailed(format!(
                "inner envelope sender_did mismatch: MLS says {sender_did}, envelope says {}",
                inner.sender_did
            )));
        }

        // Verify signature + unwrap access keys BEFORE anti-replay.
        // Signature verification must precede SequenceTracker mutation to
        // prevent an attacker from poisoning the tracker with forged envelopes
        // (which would cause the real message to be rejected as a replay).
        //
        // Recovery admin gate: check if sender has ContextClose capability
        // (admin). Only evaluated when message_type == Recovery to avoid an
        // extra lock acquisition on the normal path.
        let sender_is_admin =
            if inner.message_type == scp_protocol::envelope::inner::MessageType::Recovery {
                let contexts = self.contexts.lock().await;
                contexts.get(context_id).is_some_and(|ctx| {
                    ctx.role_state
                        .member_has_capability(&sender_did, &Capability::ContextClose)
                })
            } else {
                false // irrelevant for non-Recovery messages
            };

        let ak = access_key.ok_or_else(|| {
            ContextError::CryptoFailed(format!(
                "no access key for {local_member_did} in context {context_id}"
            ))
        })?;
        let plaintext = verify_and_unwrap(
            self,
            &inner,
            &sender_did,
            context_id,
            &local_member_did,
            &ak,
            sender_is_admin,
        )?;

        // Anti-replay + reorder buffer (§9.8.2, §9.8.5).
        // Now safe to inspect SequenceTracker — the envelope is authenticated.
        let now_ms = self.clock.now_millis();
        let sequence_check = self
            .validate_and_drain_timeouts(context_id, &inner, now_ms)
            .await?;

        match sequence_check {
            SequenceCheck::Expected => {
                // Message is in order — deliver immediately.
                self.deliver_message_and_drain_buffered(
                    context_id,
                    &context_id_bytes,
                    &sender_did,
                    &inner,
                    &plaintext,
                )
                .await?;
                Ok(Some((plaintext, sender_did)))
            }
            SequenceCheck::Ahead { expected: _ } => {
                // Message is ahead of expected — buffer it (§9.8.5).
                self.buffer_ahead_message(context_id, &inner, &sender_did, &plaintext, now_ms)
                    .await?;
                Ok(None)
            }
        }
    }

    /// Validates timestamp and sequence, then drains timed-out gaps.
    ///
    /// Returns the `SequenceCheck` result for the caller to decide whether
    /// to deliver immediately or buffer.
    async fn validate_and_drain_timeouts(
        &self,
        context_id: &str,
        inner: &scp_protocol::envelope::inner::InnerEnvelope,
        now_ms: u64,
    ) -> Result<SequenceCheck, ContextError> {
        let mut contexts = self.contexts.lock().await;
        let ctx = contexts
            .get_mut(context_id)
            .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;

        // Timestamp validation first — reject timestamps out of bounds.
        let tv = TimestampValidator::default();
        tv.validate(inner, now_ms)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // Sequence check: replay detection + gap detection (§9.8.5).
        let check = ctx
            .sequence_tracker
            .validate(inner)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // Also drain any timed-out gaps on each delivery call.
        let timed_out = ctx
            .reorder_buffer
            .drain_timed_out(now_ms, &ctx.sequence_tracker);
        for (gap_info, messages) in timed_out {
            ctx.receive_buffer.push(ContextEvent::SequenceGapDetected {
                sender_did: DID(gap_info.sender_did.clone()),
                expected_sequence: gap_info.expected_sequence,
                first_delivered_sequence: gap_info.first_buffered_sequence,
                reason: format!("{:?}", gap_info.reason),
            });
            for msg in &messages {
                // Re-check membership and capability — sender may have been
                // removed or had capability revoked while the message was
                // buffered waiting for the gap to fill.
                if !ctx.membership.contains(&msg.sender_did)
                    || ctx
                        .access
                        .write_revoked_members
                        .contains(&DID(msg.sender_did.clone()))
                    || !ctx
                        .role_state
                        .member_has_capability(&msg.sender_did, &Capability::MessagesWrite)
                {
                    continue;
                }
                ctx.sequence_tracker.advance(
                    &msg.inner.context_id,
                    &msg.sender_did,
                    msg.inner.sequence,
                    msg.inner.timestamp,
                );
                ctx.receive_buffer.push(ContextEvent::MessageReceived {
                    sender_did: DID(msg.sender_did.clone()),
                    payload: msg.plaintext.clone(),
                });
            }
        }

        Ok(check)
    }

    /// Buffers an out-of-order message that arrived ahead of expected sequence.
    ///
    /// If the buffer overflows, force-closes the oldest gap and delivers
    /// all its messages.
    async fn buffer_ahead_message(
        &self,
        context_id: &str,
        inner: &scp_protocol::envelope::inner::InnerEnvelope,
        sender_did: &str,
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<(), ContextError> {
        let buffered_msg = BufferedMessage {
            inner: inner.clone(),
            sender_did: sender_did.to_owned(),
            plaintext: plaintext.to_vec(),
            received_at: now_ms,
        };

        let mut contexts = self.contexts.lock().await;
        let ctx = contexts
            .get_mut(context_id)
            .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;

        if let Some((mut gap_info, messages)) = ctx.reorder_buffer.buffer(buffered_msg) {
            let expected = ctx
                .sequence_tracker
                .expected_sequence(context_id, sender_did)
                .unwrap_or(1);
            gap_info.expected_sequence = expected;

            ctx.receive_buffer.push(ContextEvent::SequenceGapDetected {
                sender_did: DID(gap_info.sender_did.clone()),
                expected_sequence: gap_info.expected_sequence,
                first_delivered_sequence: gap_info.first_buffered_sequence,
                reason: format!("{:?}", gap_info.reason),
            });

            for msg in &messages {
                // Re-check membership and capability — sender may have been
                // removed or had capability revoked while the message was
                // buffered (buffer overflow force-delivery).
                if !ctx.membership.contains(&msg.sender_did)
                    || ctx
                        .access
                        .write_revoked_members
                        .contains(&DID(msg.sender_did.clone()))
                    || !ctx
                        .role_state
                        .member_has_capability(&msg.sender_did, &Capability::MessagesWrite)
                {
                    continue;
                }
                ctx.sequence_tracker.advance(
                    &msg.inner.context_id,
                    &msg.sender_did,
                    msg.inner.sequence,
                    msg.inner.timestamp,
                );
                ctx.receive_buffer.push(ContextEvent::MessageReceived {
                    sender_did: DID(msg.sender_did.clone()),
                    payload: msg.plaintext.clone(),
                });
            }
        }

        Ok(())
    }

    /// Delivers a message that is in sequence order, advances the tracker,
    /// checks membership and capability, pushes the event, and then drains
    /// any consecutive buffered messages that are now unblocked.
    async fn deliver_message_and_drain_buffered(
        &self,
        context_id: &str,
        context_id_bytes: &[u8; 32],
        sender_did: &str,
        inner: &scp_protocol::envelope::inner::InnerEnvelope,
        plaintext: &[u8],
    ) -> Result<(), ContextError> {
        let sender_did_obj = DID(sender_did.to_owned());

        let mut contexts = self.contexts.lock().await;
        let ctx = contexts
            .get_mut(context_id)
            .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        require_active(&ctx.handle)?;

        // Membership + capability check.
        if !ctx.membership.contains(sender_did) {
            return Err(ContextError::MemberNotFound(format!(
                "sender {sender_did} is not a member of this context"
            )));
        }
        if ctx.access.write_revoked_members.contains(&sender_did_obj) {
            return Err(ContextError::PermissionDenied(format!(
                "write access has been revoked for {sender_did}"
            )));
        }
        if !ctx
            .role_state
            .member_has_capability(sender_did, &Capability::MessagesWrite)
        {
            return Err(ContextError::PermissionDenied(format!(
                "member {sender_did} does not have messages:write capability"
            )));
        }

        // Advance sequence tracker and deliver the in-order message.
        ctx.sequence_tracker
            .advance(context_id, sender_did, inner.sequence, inner.timestamp);
        ctx.receive_buffer.push(ContextEvent::MessageReceived {
            sender_did: sender_did_obj,
            payload: plaintext.to_vec(),
        });

        // Drain consecutive buffered messages that are now unblocked (§9.8.5).
        let next_expected = inner.sequence.saturating_add(1);
        let consecutive =
            ctx.reorder_buffer
                .drain_consecutive(context_id, sender_did, next_expected);
        for msg in &consecutive {
            // Re-check membership and capability for buffered messages — the
            // sender may have been removed or had capability revoked while the
            // message was buffered.
            if !ctx.membership.contains(&msg.sender_did)
                || ctx
                    .access
                    .write_revoked_members
                    .contains(&DID(msg.sender_did.clone()))
                || !ctx
                    .role_state
                    .member_has_capability(&msg.sender_did, &Capability::MessagesWrite)
            {
                continue;
            }
            ctx.sequence_tracker.advance(
                &msg.inner.context_id,
                &msg.sender_did,
                msg.inner.sequence,
                msg.inner.timestamp,
            );
            ctx.receive_buffer.push(ContextEvent::MessageReceived {
                sender_did: DID(msg.sender_did.clone()),
                payload: msg.plaintext.clone(),
            });
        }

        drop(contexts);

        crate::metrics::record_message_received();
        self.event_log
            .append_context_event(context_id_bytes, "MessageReceived")?;

        Ok(())
    }
}
