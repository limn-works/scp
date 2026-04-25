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
//! # Supervisor back-pointer (commit 12c.9c of ADR-049)
//!
//! The hoisted messaging helpers now take `supervisor: &Supervisor`.
//! Each forwarder resolves its supervisor through the
//! `Weak<Supervisor>` back-pointer installed on [`ContextManager`] by
//! [`Supervisor::attach_context_manager`](crate::context::supervisor::Supervisor::attach_context_manager)
//! during bridge construction. `self.supervisor().expect(...)` is the
//! canonical call shape — unwrap-or-panic is safe because the
//! bridge-construction contract attaches before any FFI caller sees
//! the `ContextManager`.
//!
//! # Transitive hoist (commit 12c.1b of ADR-049)
//!
//! Commit 12c.1b extends the hoist to every messaging transitive
//! previously defined as an inherent method on [`ContextManager`] in
//! this file:
//! [`ContextManager::encrypt_and_send`],
//! [`ContextManager::authorize_send_payment`],
//! [`ContextManager::capture_send_payment`],
//! [`ContextManager::finalize_send`],
//! [`ContextManager::decrypt_and_dispatch`],
//! [`ContextManager::validate_and_drain_timeouts`],
//! [`ContextManager::buffer_ahead_message`], and
//! [`ContextManager::deliver_message_and_drain_buffered`]. Their bodies
//! now live as free functions in [`crate::context::messaging_helpers`]
//! with the `mgr: &ContextManager` parameter + explicit-collaborator
//! shape; the inherent methods here are reduced to one-line forwarders
//! so existing callers — pipeline-wiring integration tests,
//! `manager/tests/messaging.rs`, and the hoisted
//! [`crate::context::messaging_helpers::send_message`] /
//! [`crate::context::messaging_helpers::deliver_incoming`] bodies —
//! continue to compile without signature changes. The outer shim
//! (including every forwarder in this file) is deleted in commit 12f
//! once the actor handler bodies in
//! [`crate::context::actor::handlers::messaging`] own the send /
//! receive path.

use scp_protocol::envelope::validation::SequenceCheck;

use super::{ContextError, ContextGeneration, ContextHandle, ContextManager, DID, instrument};

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
#[allow(
    dead_code,
    reason = "ADR-049 commit 12c.9e deleted the trait-based test mocks that called this; retained for 12c.9f rewire when MlsBackend injection lands"
)]
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
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::send_message — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::messaging_helpers::send_message(
            &sup,
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
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::messaging_helpers::encrypt_and_send`] free
    /// function (ADR-049 commit 12c.1b). Deleted in commit 12f.
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)] // Forwarder unreachable post-12c.9g.2 helper rewire; deleted in 12c.9g.4.
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
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::encrypt_and_send — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::messaging_helpers::encrypt_and_send(
            &sup,
            broadcast_envelope,
            signing_key,
            context_id,
            sender_did,
            payload,
            recipients_data,
            sequence,
            source_provenance,
            routing_ids,
        )
    }

    /// Authorizes escrow for send payment (Phase 1.5 of `send_message`).
    ///
    /// On failure, the caller is responsible for draining the `EconomyTicket`
    /// via `rollback_economy_ticket`. This helper MUST NOT roll back any
    /// economic state itself — doing so from here would double-refund the
    /// budget when the caller subsequently drains the ticket (F4).
    /// Returns the authorization token (if payment is required) for later
    /// capture or void.
    #[allow(dead_code)] // Forwarder unreachable post-12c.9g.2 helper rewire; deleted in 12c.9g.4.
    pub(crate) async fn authorize_send_payment(
        &self,
        context_id: &str,
        sender_did: &DID,
    ) -> Result<Option<super::economy::PaidActionAuthorization>, ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::authorize_send_payment — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::messaging_helpers::authorize_send_payment(&sup, context_id, sender_did)
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
    #[allow(dead_code)] // Forwarder unreachable post-12c.9g.2 helper rewire; deleted in 12c.9g.4.
    pub(crate) async fn capture_send_payment(
        &self,
        auth: Option<super::economy::PaidActionAuthorization>,
        sender_did: &DID,
        context_id: &str,
        deducted_cost: Option<scp_protocol::economy::types::Amount>,
    ) {
        // ADR-049 commit 12c.9c — `()`-returning forwarder: a missing
        // supervisor degrades to a no-op log (the helper logs the
        // same contract violation internally when reached directly
        // from the hoisted path).
        let Some(sup) = self.supervisor() else {
            tracing::error!(
                context_id,
                "ContextManager::capture_send_payment — Supervisor is not attached; \
                 skipping payment capture (contract violation; see ADR-049 commit 12c.9c)"
            );
            return;
        };
        crate::context::messaging_helpers::capture_send_payment(
            &sup,
            auth,
            sender_did,
            context_id,
            deducted_cost,
        )
        .await;
    }

    /// Pushes a `MessageSent` event, appends to the event log, and persists.
    ///
    /// Extracted from `send_message` Phase 3 to keep the outer function
    /// within the clippy `too_many_lines` limit.
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)] // Forwarder unreachable post-12c.9g.2 helper rewire; deleted in 12c.9g.4.
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
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::finalize_send — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::messaging_helpers::finalize_send(
            &sup,
            context_id,
            context_id_bytes,
            sender_did,
            sequence,
            payload,
            signing_key,
            ctx_gen,
        )
        .await
    }

    /// Decrypts an incoming envelope and dispatches management/control messages.
    ///
    /// Returns `Some(OpenedEnvelope)` for application messages that need further
    /// processing, or `None` for control/management messages that are handled
    /// internally.
    #[allow(dead_code)] // Forwarder unreachable post-12c.9g.2 helper rewire; deleted in 12c.9g.4.
    pub(crate) fn decrypt_and_dispatch(
        &self,
        context_id: &str,
        context_id_bytes: &[u8; 32],
        encrypted_blob: &[u8],
    ) -> Result<Option<scp_protocol::context::builder::OpenedEnvelope>, ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::decrypt_and_dispatch — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::messaging_helpers::decrypt_and_dispatch(
            &sup,
            context_id,
            context_id_bytes,
            encrypted_blob,
        )
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
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::deliver_incoming — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::messaging_helpers::deliver_incoming(
            &sup,
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
    #[allow(dead_code)] // Forwarder unreachable post-12c.9g.2 helper rewire; deleted in 12c.9g.4.
    pub(crate) async fn validate_and_drain_timeouts(
        &self,
        context_id: &str,
        inner: &scp_protocol::envelope::inner::InnerEnvelope,
        now_ms: u64,
    ) -> Result<SequenceCheck, ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::validate_and_drain_timeouts — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::messaging_helpers::validate_and_drain_timeouts(
            &sup, context_id, inner, now_ms,
        )
        .await
    }

    /// Buffers an out-of-order message that arrived ahead of expected sequence.
    ///
    /// If the buffer overflows, force-closes the oldest gap and delivers
    /// all its messages.
    #[allow(dead_code)] // Forwarder unreachable post-12c.9g.2 helper rewire; deleted in 12c.9g.4.
    pub(crate) async fn buffer_ahead_message(
        &self,
        context_id: &str,
        inner: &scp_protocol::envelope::inner::InnerEnvelope,
        sender_did: &str,
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::buffer_ahead_message — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::messaging_helpers::buffer_ahead_message(
            &sup, context_id, inner, sender_did, plaintext, now_ms,
        )
        .await
    }

    /// Delivers a message that is in sequence order, advances the tracker,
    /// checks membership and capability, pushes the event, and then drains
    /// any consecutive buffered messages that are now unblocked.
    ///
    /// `skip_velocity` is `true` when the sender is a locally-controlled DID
    /// (i.e. the same node that sent the message). In that case velocity is
    /// already recorded on the send path and must not be counted again here,
    /// otherwise a single message would be double-counted on single-node setups.
    #[allow(dead_code)] // Forwarder unreachable post-12c.9g.2 helper rewire; deleted in 12c.9g.4.
    pub(crate) async fn deliver_message_and_drain_buffered(
        &self,
        context_id: &str,
        context_id_bytes: &[u8; 32],
        sender_did: &str,
        inner: &scp_protocol::envelope::inner::InnerEnvelope,
        plaintext: &[u8],
        skip_velocity: bool,
    ) -> Result<bool, ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::deliver_message_and_drain_buffered — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::messaging_helpers::deliver_message_and_drain_buffered(
            &sup,
            context_id,
            context_id_bytes,
            sender_did,
            inner,
            plaintext,
            skip_velocity,
        )
        .await
    }
}
