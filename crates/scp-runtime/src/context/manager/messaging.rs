//! Message send and receive operations.
//!
//! # Helper hoist (commit 12b.1 of ADR-049)
//!
//! Six private helpers previously defined in this file have been moved
//! to [`crate::context::messaging_helpers`] with explicit-collaborator
//! signatures (no more `&ContextManager` or `&self`). The outer methods
//! [`ContextManager::send_message`] and [`ContextManager::deliver_incoming`]
//! call the free-function form under that module.
//!
//! # Top-level hoist (commit 12c.1 of ADR-049)
//!
//! Commit 12c.1 extends the hoist to the two top-level methods
//! [`ContextManager::send_message`] and
//! [`ContextManager::deliver_incoming`]. Their bodies now live as
//! `pub(crate) async fn`s in `messaging_helpers`; the outer methods on
//! [`ContextManager`] have been reduced to one-line forwarders that pass
//! `self` plus the clock and key resolver to the free function.
//!
//! Messaging-internal private helpers remain as inherent methods on
//! [`ContextManager`] in commit 12c.1 and are reached via the `mgr`
//! parameter from the hoisted bodies. They will be hoisted in a 12c.1
//! continuation step and deleted alongside the outer shim in commit 12f
//! once the actor handler bodies in
//! [`crate::context::actor::handlers::messaging`] own the send / receive
//! path.

use scp_protocol::envelope::validation::{BufferedMessage, SequenceCheck, TimestampValidator};

use super::{
    Capability, ContextError, ContextEvent, ContextGeneration, ContextHandle, ContextManager, DID,
    context_id_to_bytes, evaluate_consequence_rules, instrument, require_active,
};
use crate::context::messaging_helpers::{
    build_encrypted_envelope, deliver_plaintext_or_announcement, run_buffered_post_delivery,
};

/// Re-export of the protocol-level domain-separated routing ID derivation.
///
/// Uses `SHA-256("scp:context-routing:" || context_id)` to produce a
/// 32-byte routing ID distinct from the raw `context_id_bytes` (which is
/// `SHA-256(context_id)` without domain separation).
///
/// Both the send path and subscribe path MUST use this function so that
/// the relay routes messages to the correct subscribers.
///
/// # Test-only
///
/// Production callers moved to [`scp_protocol::context::context_routing_id`]
/// in commit 12b.1 (ADR-049 §"helper hoist"): the `build_encrypted_envelope`
/// free function inlines the canonical call directly. The wrapper is
/// retained here so the existing delegation-contract test in
/// `tests/messaging.rs` continues to witness the bit-identity between this
/// re-export and the protocol-level implementation.
#[cfg(test)]
pub(super) fn derive_routing_id(context_id: &str) -> [u8; 32] {
    scp_protocol::context::context_routing_id(context_id)
}

/// Default blob TTL for outer envelopes (5 minutes / 300 seconds).
/// Relays may store the blob up to this duration for offline recipients.
pub const DEFAULT_BLOB_TTL_SECS: u32 = 300;

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
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::messaging_helpers::send_message`] free function
    /// (ADR-049 commit 12c.1). Deleted in commit 12f alongside every
    /// other `ContextManager` messaging surface.
    #[instrument(skip_all, fields(context_id = handle.context_id()))]
    pub async fn send_message(
        &self,
        handle: &ContextHandle,
        sender_did: &DID,
        payload: &[u8],
        signing_key: Option<&ed25519_dalek::SigningKey>,
        source_provenance: Option<&scp_protocol::provenance::attach::SourceContextInfo>,
        spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    ) -> Result<(), ContextError> {
        crate::context::messaging_helpers::send_message(
            self,
            self.clock_ref(),
            self.key_resolver_ref(),
            handle,
            sender_did,
            payload,
            signing_key,
            source_provenance,
            spending_ucan,
        )
        .await
    }

    /// Encrypts the payload and sends it via transport (Phase 2 of `send_message`).
    ///
    /// For pseudonym routing (§9.10.4), `routing_ids` may contain multiple
    /// targets: each member's pseudonym plus the shared context routing ID
    /// as a fallback. The encrypted blob is computed once and sent to each
    /// routing ID.
    ///
    /// Extracted to keep `send_message` within the clippy `too_many_lines` limit.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn encrypt_and_send(
        &self,
        broadcast_envelope: Option<scp_protocol::crypto::sender_keys::broadcast::BroadcastEnvelope>,
        signing_key: Option<&ed25519_dalek::SigningKey>,
        context_id: &str,
        sender_did: &DID,
        payload: &[u8],
        recipients_data: &std::collections::HashMap<
            String,
            scp_protocol::crypto::access_keys::AccessKey,
        >,
        sequence: u64,
        source_provenance: Option<&scp_protocol::provenance::attach::SourceContextInfo>,
        routing_ids: &[[u8; 32]],
    ) -> Result<(), ContextError> {
        let encrypted = if let Some(envelope) = broadcast_envelope {
            rmp_serde::to_vec_named(&envelope)
                .map_err(|e| ContextError::CryptoFailed(format!("envelope serialization: {e}")))?
        } else {
            let encrypt_start = std::time::Instant::now();
            let sk = signing_key.ok_or_else(|| {
                ContextError::CryptoFailed("signing key required for encrypted send".into())
            })?;
            let result = build_encrypted_envelope(
                &self.clock,
                &self.crypto,
                context_id,
                sender_did,
                payload,
                sk,
                recipients_data,
                sequence,
                source_provenance,
            )?;
            crate::metrics::record_encrypt_duration(encrypt_start.elapsed());
            result
        };
        // §9.10.4: fan-out — seal once, send to all routing IDs.
        // Best-effort: only fail if ALL sends fail. A partial fan-out
        // (some routing IDs succeed, others fail) is acceptable — at least
        // some members will receive the message. Record a metric per
        // successful send to avoid undercounting (Bug 6).
        let mut last_err = None;
        let mut any_success = false;
        for rid in routing_ids {
            match self.transport.send_message(rid, &encrypted) {
                Ok(()) => {
                    any_success = true;
                    crate::metrics::record_message_sent();
                }
                Err(e) => {
                    tracing::warn!(routing_id = ?rid, error = %e, "fan-out send failed");
                    last_err = Some(e);
                }
            }
        }
        if !any_success {
            return Err(last_err.unwrap_or_else(|| {
                ContextError::TransportFailed("all fan-out sends failed".into())
            }));
        }
        Ok(())
    }

    /// Authorizes escrow for send payment (Phase 1.5 of `send_message`).
    ///
    /// On failure, the caller is responsible for draining the `EconomyTicket`
    /// via `rollback_economy_ticket`. This helper MUST NOT roll back any
    /// economic state itself — doing so from here would double-refund the
    /// budget when the caller subsequently drains the ticket (F4).
    /// Returns the authorization token (if payment is required) for later
    /// capture or void.
    pub(crate) async fn authorize_send_payment(
        &self,
        context_id: &str,
        sender_did: &DID,
    ) -> Result<Option<super::economy::PaidActionAuthorization>, ContextError> {
        self.authorize_paid_action(
            scp_protocol::economy::types::PaidActionType::MessageSend,
            sender_did,
            context_id,
        )
        .await
    }

    /// Captures the escrow hold after a successful send (Phase 3 of `send_message`).
    ///
    /// Best-effort: if capture fails, logs a warning but does NOT roll back
    /// the budget and does NOT fail the send. The message was already
    /// delivered -- the service was rendered, so the budget deduction stands.
    /// Rolling back on capture failure would let senders consume the service
    /// for free whenever the payment adapter is flaky (H8).
    ///
    /// On failure a `PaymentCaptureFailed` entry is appended to the event log
    /// and pushed to the receive buffer to provide a durable audit trail (H19).
    pub(crate) async fn capture_send_payment(
        &self,
        auth: Option<super::economy::PaidActionAuthorization>,
        sender_did: &DID,
        context_id: &str,
        deducted_cost: Option<scp_protocol::economy::types::Amount>,
    ) {
        if let Some(a) = auth
            && let Err(e) = self.complete_paid_action(a, sender_did, context_id).await
        {
            // H8: do NOT rollback budget — service was delivered.
            tracing::warn!(
                context_id,
                "payment capture failed after successful send: {e}"
            );
            // H19: append durable audit record to event log + receive buffer.
            self.record_payment_capture_failure(
                context_id,
                "send_message",
                sender_did,
                &e.to_string(),
                deducted_cost,
            )
            .await;
        }
    }

    /// Pushes a `MessageSent` event, appends to the event log, and persists.
    ///
    /// Extracted from `send_message` Phase 3 to keep the outer function
    /// within the clippy `too_many_lines` limit.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finalize_send(
        &self,
        context_id: &str,
        context_id_bytes: &[u8; 32],
        sender_did: &DID,
        sequence: u64,
        payload: &[u8],
        signing_key: Option<&ed25519_dalek::SigningKey>,
        ctx_gen: &ContextGeneration,
    ) -> Result<(), ContextError> {
        // M12: Append event log BEFORE consequence evaluation so that
        // event_log_entries_for_consequences sees the current event.
        // Periodic consequence timers only read from the event log (not
        // the receive buffer), so the event must be persisted first.
        self.event_log.append_context_event(
            context_id_bytes,
            "MessageSent",
            sender_did.as_ref(),
        )?;
        // Phase 3 reacquire with generation check — detects if the context
        // was removed and recreated between Phase 1 and Phase 3.
        {
            let now = self.clock.now_secs();
            if let Ok(mut guard) = self.relock_context(ctx_gen).await {
                let ctx = &mut *guard;
                if require_active(&ctx.handle).is_err() {
                    // Context expired during Phase 2 — rollback the sequence
                    // number to prevent a permanent gap (Fix 6).
                    ctx.membership.rollback_sequence_number(sender_did);
                    return Ok(());
                }
                let sent_event = ContextEvent::MessageSent {
                    sender_did: sender_did.clone(),
                    sequence_number: sequence,
                    payload: payload.to_vec(),
                };
                ctx.emit_event(sent_event, context_id, self.event_tx.as_ref());

                // Velocity already recorded in send_message Phase 1 (M4: before
                // economy enforcement). No duplicate record_message here.

                // Consequence enforcement (#1531) — evaluate rules, then dispatch.
                // evaluate_consequence_rules is called here so the pipeline wiring
                // gate can detect it in messaging.rs (not hidden inside dispatch_consequences).
                //
                // The same event snapshot is reused for both consequence evaluation
                // and participation record computation (finding #46 dedup).
                let send_events = super::governance::event_log_entries_for_consequences(
                    ctx,
                    context_id,
                    now,
                    &*self.event_log,
                );
                let consequence_rules: Vec<super::ConsequenceRule> =
                    ctx.governance.consequence_rules.clone();
                // evaluate_consequence_rules is called as an expression_statement
                // (not a let_declaration) so the NO-DISCARD-MSG gate passes.
                let send_triggered = evaluate_consequence_rules(
                    &consequence_rules,
                    &send_events,
                    sender_did.as_ref(),
                    now,
                );
                super::governance::enforce_triggered_consequences(
                    ctx,
                    &super::governance::EnforceConsequencesCtx {
                        context_id,
                        member_did: sender_did,
                        now,
                        triggered: &send_triggered,
                        rules: &consequence_rules,
                        clock: &*self.clock,
                        event_log: &*self.event_log,
                        event_tx: self.event_tx.as_ref(),
                    },
                );

                // Participation record update (#1530) — refresh cache after send.
                // Reuses `send_events` from above to avoid a second
                // event_log_entries_for_consequences call.
                let send_merkle = self
                    .event_log
                    .event_log_merkle_root(context_id_bytes)
                    .unwrap_or([0u8; 32]);
                if !send_events.is_empty()
                    && let Ok(record) =
                        scp_protocol::trust::participation::compute_participation_record(
                            &send_events,
                            sender_did.as_ref(),
                            context_id,
                            send_merkle,
                            now,
                        )
                    && record.participation_count > 0
                {
                    ctx.governance
                        .participation_cache
                        .insert(sender_did.to_string(), record);
                }

                // Checkpoint tracking (§9.9.3): increment event counter and
                // create a checkpoint if the event or time threshold is met.
                ctx.checkpoint_events_since += 1;
                if let Some(sk) = signing_key {
                    self.create_checkpoint_if_due(context_id, ctx, sender_did, sk);
                }
            } else {
                tracing::warn!(
                    context_id,
                    "finalize_send: generation mismatch or context removed — \
                     consequence evaluation skipped"
                );
            }
        }
        if self.has_persistence()
            && let Ok(guard) = self.relock_context(ctx_gen).await
        {
            let ctx = &*guard;
            let snapshot = Self::snapshot_context(ctx);
            self.persist_context_snapshot(context_id, snapshot);
        }
        Ok(())
    }

    /// Decrypts an incoming envelope and dispatches management/control messages.
    ///
    /// Returns `Some(OpenedEnvelope)` for application messages that need further
    /// processing, or `None` for control/management messages that are handled
    /// internally.
    pub(crate) fn decrypt_and_dispatch(
        &self,
        context_id: &str,
        context_id_bytes: &[u8; 32],
        encrypted_blob: &[u8],
    ) -> Result<Option<scp_protocol::context::builder::OpenedEnvelope>, ContextError> {
        let decrypt_start = std::time::Instant::now();
        let open_result = self.crypto.open(context_id_bytes, encrypted_blob)?;
        crate::metrics::record_decrypt_duration(decrypt_start.elapsed());

        match open_result {
            scp_protocol::context::builder::OpenResult::Application(env) => Ok(Some(*env)),
            scp_protocol::context::builder::OpenResult::Control => Ok(None),
            scp_protocol::context::builder::OpenResult::Management {
                sender_did,
                payload,
            } => {
                tracing::debug!(sender_did = %sender_did, context_id = %context_id, "received MLS-wrapped management message");
                self.crypto
                    .process_incoming_sender_key(context_id_bytes, &sender_did, &payload)?;
                Ok(None)
            }
        }
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
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::messaging_helpers::deliver_incoming`] free
    /// function (ADR-049 commit 12c.1). Deleted in commit 12f alongside
    /// every other `ContextManager` messaging surface.
    #[instrument(skip_all, fields(context_id))]
    pub async fn deliver_incoming(
        &self,
        context_id: &str,
        encrypted_blob: &[u8],
    ) -> Result<Option<(Vec<u8>, String)>, ContextError> {
        crate::context::messaging_helpers::deliver_incoming(
            self,
            self.clock_ref(),
            self.key_resolver_ref(),
            context_id,
            encrypted_blob,
        )
        .await
    }

    /// Validates timestamp and sequence, then drains timed-out gaps.
    ///
    /// Returns the `SequenceCheck` result for the caller to decide whether
    /// to deliver immediately or buffer.
    pub(crate) async fn validate_and_drain_timeouts(
        &self,
        context_id: &str,
        inner: &scp_protocol::envelope::inner::InnerEnvelope,
        now_ms: u64,
    ) -> Result<SequenceCheck, ContextError> {
        let ctx_arc = self
            .get_context_arc(context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;

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
        let context_id_bytes = context_id_to_bytes(context_id);
        let timed_out = ctx
            .reorder_buffer
            .drain_timed_out(now_ms, &ctx.sequence_tracker);
        for (gap_info, messages) in timed_out {
            let gap_event = ContextEvent::SequenceGapDetected {
                sender_did: DID(gap_info.sender_did.clone()),
                expected_sequence: gap_info.expected_sequence,
                first_delivered_sequence: gap_info.first_buffered_sequence,
                reason: format!("{:?}", gap_info.reason),
            };
            ctx.emit_event(gap_event, context_id, self.event_tx.as_ref());
            for msg in &messages {
                // Re-check membership and capability — sender may have been
                // removed or had capability revoked while the message was
                // buffered waiting for the gap to fill.
                if !ctx.membership.contains(&msg.sender_did)
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
                if let Some(event_name) = deliver_plaintext_or_announcement(
                    ctx,
                    &msg.sender_did,
                    &msg.plaintext,
                    context_id,
                    self.event_tx.as_ref(),
                ) {
                    // Bug fix (#1534): buffered messages now receive the same
                    // post-delivery governance treatment as directly delivered
                    // messages — velocity, event log, consequence evaluation.
                    run_buffered_post_delivery(
                        ctx,
                        context_id,
                        &context_id_bytes,
                        &msg.sender_did,
                        event_name,
                        &*self.clock,
                        &*self.event_log,
                        self.event_tx.as_ref(),
                    );
                }
            }
        }

        Ok(check)
    }

    /// Buffers an out-of-order message that arrived ahead of expected sequence.
    ///
    /// If the buffer overflows, force-closes the oldest gap and delivers
    /// all its messages.
    pub(crate) async fn buffer_ahead_message(
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

        let ctx_arc = self
            .get_context_arc(context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;

        if let Some((mut gap_info, messages)) = ctx.reorder_buffer.buffer(buffered_msg) {
            let context_id_bytes = context_id_to_bytes(context_id);
            let expected = ctx
                .sequence_tracker
                .expected_sequence(context_id, sender_did)
                .unwrap_or(1);
            gap_info.expected_sequence = expected;

            let gap_event = ContextEvent::SequenceGapDetected {
                sender_did: DID(gap_info.sender_did.clone()),
                expected_sequence: gap_info.expected_sequence,
                first_delivered_sequence: gap_info.first_buffered_sequence,
                reason: format!("{:?}", gap_info.reason),
            };
            ctx.emit_event(gap_event, context_id, self.event_tx.as_ref());

            for msg in &messages {
                // Re-check membership and capability — sender may have been
                // removed or had capability revoked while the message was
                // buffered (buffer overflow force-delivery).
                if !ctx.membership.contains(&msg.sender_did)
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
                if let Some(event_name) = deliver_plaintext_or_announcement(
                    ctx,
                    &msg.sender_did,
                    &msg.plaintext,
                    context_id,
                    self.event_tx.as_ref(),
                ) {
                    // Bug fix (#1534): overflow-forced delivery now runs
                    // consequence evaluation, matching the direct path.
                    run_buffered_post_delivery(
                        ctx,
                        context_id,
                        &context_id_bytes,
                        &msg.sender_did,
                        event_name,
                        &*self.clock,
                        &*self.event_log,
                        self.event_tx.as_ref(),
                    );
                }
            }
        }

        Ok(())
    }

    /// Delivers a message that is in sequence order, advances the tracker,
    /// checks membership and capability, pushes the event, and then drains
    /// any consecutive buffered messages that are now unblocked.
    ///
    /// `skip_velocity` is `true` when the sender is a locally-controlled DID
    /// (i.e. the same node that sent the message). In that case velocity is
    /// already recorded on the send path and must not be counted again here,
    /// otherwise a single message would be double-counted on single-node setups.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn deliver_message_and_drain_buffered(
        &self,
        context_id: &str,
        context_id_bytes: &[u8; 32],
        sender_did: &str,
        inner: &scp_protocol::envelope::inner::InnerEnvelope,
        plaintext: &[u8],
        skip_velocity: bool,
    ) -> Result<bool, ContextError> {
        let sender_did_obj = DID(sender_did.to_owned());

        let ctx_arc = self
            .get_context_arc(context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;
        require_active(&ctx.handle)?;

        // Membership + capability check.
        if !ctx.membership.contains(sender_did) {
            return Err(ContextError::MemberNotFound(format!(
                "sender {sender_did} is not a member of this context"
            )));
        }
        // Suspension-aware capability check handles both role-based and
        // suspension-based denial via the single source of truth at
        // `member_has_capability` (folds `suspended_capabilities` first).
        if !ctx
            .role_state
            .member_has_capability(sender_did, &Capability::MessagesWrite)
        {
            let is_suspended = ctx
                .role_state
                .suspended_capabilities
                .get(sender_did)
                .is_some_and(|s| s.contains(&Capability::MessagesWrite));
            let msg = if is_suspended {
                format!("member {sender_did} write access has been revoked")
            } else {
                format!("member {sender_did} does not have messages:write capability")
            };
            return Err(ContextError::PermissionDenied(msg));
        }

        // §9.10.4: check if this is a pseudonym announcement before treating
        // as a regular message. Announcements are internal protocol messages
        // that update the pseudonym registry — they are NOT forwarded to the
        // application receive buffer as regular MessageReceived events.
        //
        // KNOWN LIMITATION (§9.10.4 vs §9.10.4.A): Spec says receivers should verify
        // the pseudonym-to-DID mapping, but the privacy model (pseudonym_secret from
        // private key) makes independent verification impossible. We trust MLS-
        // authenticated senders to honestly announce their pseudonyms. A malicious
        // member can only misdirect their own message copies.
        if let Ok(announcement) = rmp_serde::from_slice::<super::PseudonymAnnouncement>(plaintext)
            && announcement.tag == super::PSEUDONYM_ANNOUNCEMENT_TAG
        {
            // Bug fix: verify announcement.member_did matches the MLS-authenticated
            // sender_did. Without this check, any member could forge a pseudonym
            // announcement for another member, redirecting their messages.
            if announcement.member_did != sender_did {
                tracing::warn!(
                    context_id,
                    sender_did,
                    claimed_did = %announcement.member_did,
                    "pseudonym announcement sender mismatch — rejecting forged announcement"
                );
                return Err(ContextError::PermissionDenied(format!(
                    "pseudonym announcement member_did ({}) does not match sender ({sender_did})",
                    announcement.member_did
                )));
            }
            let announced_did = DID(announcement.member_did.clone());
            ctx.pseudonym_registry
                .insert(announced_did.clone(), announcement.pseudonym);
            let announce_event = ContextEvent::PseudonymAnnounced {
                member_did: announced_did,
                pseudonym: announcement.pseudonym,
            };
            ctx.emit_event(announce_event, context_id, self.event_tx.as_ref());
            // Advance sequence tracker for the announcement message.
            ctx.sequence_tracker
                .advance(context_id, sender_did, inner.sequence, inner.timestamp);
            // Skip the normal message delivery path — announcements are
            // consumed by the protocol, not forwarded to the application.
            // Still drain buffered messages that may now be unblocked.
            let next_expected = inner.sequence.saturating_add(1);
            let consecutive =
                ctx.reorder_buffer
                    .drain_consecutive(context_id, sender_did, next_expected);
            for msg in &consecutive {
                if !ctx.membership.contains(&msg.sender_did)
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
                if let Some(event_name) = deliver_plaintext_or_announcement(
                    ctx,
                    &msg.sender_did,
                    &msg.plaintext,
                    context_id,
                    self.event_tx.as_ref(),
                ) {
                    // Bug fix (#1534): drain_consecutive within announcement
                    // path now runs consequence evaluation per message.
                    run_buffered_post_delivery(
                        ctx,
                        context_id,
                        context_id_bytes,
                        &msg.sender_did,
                        event_name,
                        &*self.clock,
                        &*self.event_log,
                        self.event_tx.as_ref(),
                    );
                }
            }

            // Velocity, consequence, event log — same as normal messages.
            // Bug fix (#1534): consequence evaluation was previously missing from
            // the announcement path, allowing a malicious member to send
            // announcements at high velocity without triggering rate-limiting
            // consequences. Now both paths share identical post-delivery logic.
            let now = self.clock.now_secs();
            if !skip_velocity {
                ctx.governance
                    .velocity_tracker
                    .record_message(&DID(sender_did.to_owned()), now);
            }
            if let Err(e) = self.event_log.append_context_event(
                context_id_bytes,
                "PseudonymAnnounced",
                sender_did,
            ) {
                tracing::warn!(
                    context_id,
                    sender_did,
                    "failed to append PseudonymAnnounced to event log: {e}"
                );
            }
            let consequence_rules: Vec<super::ConsequenceRule> =
                ctx.governance.consequence_rules.clone();
            if !consequence_rules.is_empty() {
                let recv_events = super::governance::event_log_entries_for_consequences(
                    ctx,
                    context_id,
                    now,
                    &*self.event_log,
                );
                let recv_triggered =
                    evaluate_consequence_rules(&consequence_rules, &recv_events, sender_did, now);
                let recv_member_did = DID(sender_did.to_owned());
                super::governance::enforce_triggered_consequences(
                    ctx,
                    &super::governance::EnforceConsequencesCtx {
                        context_id,
                        member_did: &recv_member_did,
                        now,
                        triggered: &recv_triggered,
                        rules: &consequence_rules,
                        clock: &*self.clock,
                        event_log: &*self.event_log,
                        event_tx: self.event_tx.as_ref(),
                    },
                );
            }
            ctx.checkpoint_events_since += 1;

            return Ok(true);
        }

        // Advance sequence tracker and deliver the in-order message.
        ctx.sequence_tracker
            .advance(context_id, sender_did, inner.sequence, inner.timestamp);
        let recv_event = ContextEvent::MessageReceived {
            sender_did: sender_did_obj,
            payload: plaintext.to_vec(),
        };
        ctx.emit_event(recv_event, context_id, self.event_tx.as_ref());

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
            if let Some(event_name) = deliver_plaintext_or_announcement(
                ctx,
                &msg.sender_did,
                &msg.plaintext,
                context_id,
                self.event_tx.as_ref(),
            ) {
                // Bug fix (#1534): drain_consecutive within normal message
                // path now runs consequence evaluation per message.
                run_buffered_post_delivery(
                    ctx,
                    context_id,
                    context_id_bytes,
                    &msg.sender_did,
                    event_name,
                    &*self.clock,
                    &*self.event_log,
                    self.event_tx.as_ref(),
                );
            }
        }

        // H5: Append the durable event log entry for `MessageReceived` BEFORE
        // running the receive-side consequence evaluation block below. This
        // mirrors the M12 fix on the send-side `finalize_send` and preserves
        // the invariant that rule triggers reading
        // `event_log_entries_for_consequences` observe the just-delivered
        // message.
        //
        // The receive buffer (Source 2 of `event_log_entries_for_consequences`)
        // does contain the just-pushed event in fresh conditions, but the
        // dedup filter at `governance::event_log_entries_for_consequences`
        // (`estimated_ts <= last_log_ts && last_log_ts > 0`) drops buffer
        // entries whose estimated timestamp is at or before the latest event
        // log entry — and the receive buffer is also bounded by both
        // `DEFAULT_BUFFER_CAPACITY = 1000` and `MAX_BUFFER_EVENT_AGE_SECS =
        // 3600`. Without the durable append happening first, the just-
        // received message becomes invisible to the receive-side eval whenever
        // any of those bounds are crossed.
        //
        // The append is performed while the contexts mutex is still held so
        // that a crash between append and consequence evaluation leaves a
        // consistent Merkle-anchored record. If the persistence layer fails
        // we WARN and continue: the receive buffer already holds the message,
        // and dropping the whole delivery on a log-append failure is too
        // strict — the receiver has already validated decryption, signature,
        // membership, capability, and sequence.
        if let Err(e) =
            self.event_log
                .append_context_event(context_id_bytes, "MessageReceived", sender_did)
        {
            tracing::warn!(
                context_id,
                sender_did,
                "failed to append MessageReceived to event log on receive path: {e}"
            );
        }
        // H16: Defense-in-depth velocity tracking and consequence evaluation
        // for the sender on the receive path. This ensures that even if the
        // sender's node doesn't enforce consequences, the receiver still
        // evaluates rules against incoming messages.
        //
        // Skip velocity recording when `skip_velocity` is true — this happens
        // when the sender is a locally-controlled DID. On single-node setups
        // the send path already recorded velocity; counting it again here would
        // double-count the message and inflate consequence trigger counters.
        let now = self.clock.now_secs();
        if !skip_velocity {
            ctx.governance
                .velocity_tracker
                .record_message(&DID(sender_did.to_owned()), now);
        }
        let consequence_rules: Vec<super::ConsequenceRule> =
            ctx.governance.consequence_rules.clone();
        if !consequence_rules.is_empty() {
            let recv_events = super::governance::event_log_entries_for_consequences(
                ctx,
                context_id,
                now,
                &*self.event_log,
            );
            let recv_triggered =
                evaluate_consequence_rules(&consequence_rules, &recv_events, sender_did, now);
            let recv_member_did = DID(sender_did.to_owned());
            super::governance::enforce_triggered_consequences(
                ctx,
                &super::governance::EnforceConsequencesCtx {
                    context_id,
                    member_did: &recv_member_did,
                    now,
                    triggered: &recv_triggered,
                    rules: &consequence_rules,
                    clock: &*self.clock,
                    event_log: &*self.event_log,
                    event_tx: self.event_tx.as_ref(),
                },
            );
        }

        // Checkpoint tracking (§9.9.3): increment event counter on receive.
        // Checkpoints are only created on the send path (where a signing key
        // is available), but the counter must reflect all event log appends
        // including received messages to maintain accurate thresholds.
        ctx.checkpoint_events_since += 1;

        crate::metrics::record_message_received();

        Ok(false)
    }
}
