// Module-level allow — the legacy inherent-impl form in
// `manager/broadcast.rs` carried `#[allow(clippy::significant_drop_tightening)]`
// on its impl block. The hoisted bodies preserve the same lock-hold-across-await
// patterns deliberately (narrowing changes lock-ordering semantics); allowing
// the lint crate-locally keeps the hoist byte-identical to the legacy behavior.
#![allow(clippy::significant_drop_tightening)]

//! Legacy broadcast-domain helpers
//! (ADR-049 Phase 2A.5, `broadcast` domain migration).
//!
//! # Purpose
//!
//! This module preserves the pre-migration `&Supervisor` lock-and-call
//! broadcast helper bodies for the Phase 2A shim fallback. The live
//! actor path now calls [`crate::context::broadcast_helpers`], which owns
//! per-context state directly; the shim path keeps these legacy twins until
//! Phase 2A finalization removes all `*_helpers_legacy.rs` modules.
//!
//! # Behavior preservation
//!
//! Every hoisted free function is **behavior-preserving by construction**.
//! Its body is a verbatim copy of the legacy inherent method's body with
//! `self.X` replaced by either:
//!
//! - `supervisor.X_ref().ok_or(NotInitialized)?` for provider slots lifted
//!   to the supervisor (crypto, transport, `event_log`, `event_tx`,
//!   clock, `local_dids` — see ADR-049 commit 12c.9a/9b), or
//! - `manager_methods::X(supervisor, ...)` /
//!   `<domain>_helpers::X(supervisor, ...)` for the cross-domain and
//!   per-domain free-function helpers hoisted from `ContextManager` in
//!   ADR-049 commit 12c.9g.1. Helper bodies no longer derive a manager
//!   binding — every legacy callsite migrated to a direct free-function
//!   call in commit 12c.9g.2.
//!
//! The legacy inherent methods on
//! [`Supervisor`](crate::context::supervisor::Supervisor) remain as
//! one-line forwarders; they thread `self.supervisor()` into each helper
//! through the `Weak<Supervisor>` back-pointer installed by
//! [`Supervisor::with_providers`](crate::context::supervisor::Supervisor::with_providers)
//! during bridge construction. These forwarders are deleted alongside
//! the outer shim in a later ADR-049 commit when the actor handler
//! body owns the broadcast path directly.
//!
//! # Legacy twins
//!
//! [`subscribe_broadcast_legacy`], [`unsubscribe_broadcast_legacy`],
//! [`publish_broadcast_legacy`], [`publish_broadcast_content_legacy`],
//! [`block_broadcast_subscriber_legacy`], [`unblock_broadcast_subscriber_legacy`],
//! [`handle_broadcast_key_request_legacy`], [`broadcast_subscriber_count_legacy`],
//! [`is_broadcast_subscriber_legacy`], [`broadcast_admission_legacy`].

use std::hash::BuildHasher;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::broadcast::{
    BlockResult, BroadcastAdmission, BroadcastContext, KeyRequestDecision, SubscriptionResult,
    UnsubscribeResult,
};
use scp_protocol::context::broadcast_content::{BroadcastContent, serialize_broadcast_content};
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::roles::Capability;
use scp_protocol::crypto::sender_keys::BroadcastEnvelope;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::crypto::ucan::validate::{
    DidResolver, NonceTracker, ProofResolver, RevocationChecker, ValidationContext,
};

use crate::context::manager_methods;
use crate::context::state::{context_id_to_bytes, require_active};
use crate::context::supervisor::Supervisor;

// Phase 1 fix-up of ADR-049 (post-review-round-1): per-helper
// `ATTACHED_EXPECT` constants consolidated to the single
// `PROVIDER_NOT_INITIALIZED` definition in `manager_methods`.
use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED as ATTACHED_EXPECT;

// ---------------------------------------------------------------------------
// 1. subscribe_broadcast_legacy (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Subscribes a DID to a broadcast context.
///
/// Hoisted body of the legacy
/// [`ContextManager::subscribe_broadcast_legacy`](crate::context::broadcast_helpers::subscribe_broadcast_legacy)
/// (ADR-049 commit 12). See the legacy method's doc comment for the
/// full semantics. Byte-identical behavior.
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::MembershipFailed`] if the context is not a broadcast
///   context or the subscriber is already registered.
/// - [`ContextError::PermissionDenied`] if the context is gated and no
///   valid `messagesRead` UCAN is supplied.
pub async fn subscribe_broadcast_legacy<D, N, R, P, S>(
    supervisor: &Supervisor,
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
        let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;

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
        let snapshot = if manager_methods::has_persistence(supervisor) {
            Some(bc.to_snapshot())
        } else {
            None
        };

        // Add subscriber to membership tracking (role = "subscriber").
        ctx.membership
            .add_member(subscriber_did.clone(), "subscriber".into(), vec![]);

        // Push event to receive buffer.
        ctx.emit_event(result.event.clone(), context_id, supervisor.event_tx_ref());

        (result, snapshot)
    };
    // Lock dropped.

    // Persist broadcast state for crash recovery.
    if let Some(ref snapshot) = snapshot {
        manager_methods::persist_broadcast_snapshot(supervisor, context_id, snapshot);
    }

    // Persist context state after subscribe (best-effort).
    if manager_methods::has_persistence(supervisor)
        && let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id)
    {
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;
        let ctx_snapshot = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, context_id, ctx_snapshot);
    }

    // Append event to persistent event log.
    supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
        .append_context_event(&context_id_bytes, "MemberJoined", subscriber_did.as_ref())?;
    {
        if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id) {
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            ctx.checkpoint_events_since += 1;
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// 2. unsubscribe_broadcast_legacy (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Unsubscribes a DID from a broadcast context.
///
/// Hoisted body of the legacy
/// [`ContextManager::unsubscribe_broadcast_legacy`](crate::context::broadcast_helpers::unsubscribe_broadcast_legacy)
/// (ADR-049 commit 12). Byte-identical behavior.
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::MembershipFailed`] if the context is not a broadcast
///   context.
pub async fn unsubscribe_broadcast_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    subscriber_did: &DID,
    rotate_keys: bool,
) -> Result<UnsubscribeResult, ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    let (result, snapshot) = {
        let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;

        require_active(&ctx.handle)?;

        let bc = ctx
            .broadcast_context
            .as_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        let result = bc.unsubscribe(subscriber_did, rotate_keys)?;

        // Take snapshot for persistence before dropping lock (skip if
        // no persistence provider is configured).
        let snapshot = if manager_methods::has_persistence(supervisor) {
            Some(bc.to_snapshot())
        } else {
            None
        };

        // Remove from membership tracking.
        ctx.membership.remove_member(subscriber_did);

        // Emit MemberLeft event to receive buffer.
        let left_event = ContextEvent::MemberLeft {
            member_did: subscriber_did.clone(),
        };
        ctx.emit_event(left_event, context_id, supervisor.event_tx_ref());

        (result, snapshot)
    };
    // Lock dropped.

    // Persist broadcast state for crash recovery.
    if let Some(ref snapshot) = snapshot {
        manager_methods::persist_broadcast_snapshot(supervisor, context_id, snapshot);
    }

    // Persist context state after unsubscribe (best-effort).
    if manager_methods::has_persistence(supervisor)
        && let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id)
    {
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;
        let ctx_snapshot = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, context_id, ctx_snapshot);
    }

    supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
        .append_context_event(&context_id_bytes, "MemberLeft", subscriber_did.as_ref())?;
    {
        if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id) {
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            ctx.checkpoint_events_since += 1;
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// 3. publish_broadcast_legacy (top-level, actor-handler entry point — custody-generic)
// ---------------------------------------------------------------------------

/// Publishes a message to a broadcast context.
///
/// Hoisted body of the legacy
/// [`ContextManager::publish_broadcast_legacy`](crate::context::broadcast_helpers::publish_broadcast_legacy)
/// (ADR-049 commit 12). See the legacy method's doc comment for the
/// full semantics. Byte-identical behavior.
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::MembershipFailed`] if the context is not broadcast.
/// - [`ContextError::PermissionDenied`] if the sender is not an author.
pub async fn publish_broadcast_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    author_did: &DID,
    payload: &[u8],
    custody: &impl scp_platform::KeyCustody,
    signing_key_handle: &scp_platform::KeyHandle,
) -> Result<BroadcastEnvelope, ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    let envelope = {
        let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;

        require_active(&ctx.handle)?;

        // Suspension-aware capability check (§9.17, ADR-038). In
        // broadcast contexts, authors may be registered with the
        // BroadcastContext without being members of the role_state, so
        // we check the suspension overlay directly: only members whose
        // MessagesWrite capability has been explicitly suspended via
        // governance Revoke are blocked here. The downstream
        // `bc.publish` enforces author registration.
        if ctx
            .role_state
            .suspended_capabilities
            .get(author_did.as_ref())
            .is_some_and(|s| s.contains(&Capability::MessagesWrite))
        {
            return Err(ContextError::PermissionDenied(format!(
                "write access has been suspended for {author_did}"
            )));
        }

        let bc = ctx
            .broadcast_context
            .as_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        let timestamp = supervisor
            .clock_ref()
            .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
            .now_millis();

        // Compute the signing payload externally so we can sign via
        // key custody (async) while keeping seal_broadcast synchronous.
        let meta = bc.publish_metadata(author_did)?;
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
        )
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

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

        let sent_event = ContextEvent::MessageSent {
            sender_did: author_did.clone(),
            sequence_number: seq,
            payload: payload.to_vec(),
        };
        ctx.emit_event(sent_event, context_id, supervisor.event_tx_ref());

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
    supervisor
        .transport_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
        .send_message(&context_id_bytes, &envelope_bytes)?;

    // Append event to persistent event log.
    supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
        .append_context_event(&context_id_bytes, "MessageSent", author_did.as_ref())?;
    {
        if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id) {
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            ctx.checkpoint_events_since += 1;
        }
    }

    Ok(envelope)
}

// ---------------------------------------------------------------------------
// 4. publish_broadcast_content_legacy (top-level, actor-handler entry point — custody-generic)
// ---------------------------------------------------------------------------

/// Publishes a [`BroadcastContent`] to a broadcast context.
///
/// Hoisted body of the legacy
/// [`ContextManager::publish_broadcast_content_legacy`](crate::context::broadcast_helpers::publish_broadcast_content_legacy)
/// (ADR-049 commit 12). Serializes the `BroadcastContent` with the
/// magic prefix and delegates to [`publish_broadcast_legacy`]. Byte-identical
/// behavior.
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::MembershipFailed`] if the context is not broadcast.
/// - [`ContextError::PermissionDenied`] if the sender is not an author.
/// - [`ContextError::CryptoFailed`] if serialization fails.
pub async fn publish_broadcast_content_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    author_did: &DID,
    content: BroadcastContent,
    custody: &impl scp_platform::KeyCustody,
    signing_key_handle: &scp_platform::KeyHandle,
) -> Result<BroadcastEnvelope, ContextError> {
    let payload = serialize_broadcast_content(&content)
        .map_err(|e| ContextError::CryptoFailed(format!("content serialization failed: {e}")))?;
    publish_broadcast_legacy(
        supervisor,
        context_id,
        author_did,
        &payload,
        custody,
        signing_key_handle,
    )
    .await
}

// ---------------------------------------------------------------------------
// 5. block_broadcast_subscriber_legacy (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Blocks a subscriber from receiving future broadcast keys from a
/// specific author.
///
/// Hoisted body of the legacy
/// [`ContextManager::block_broadcast_subscriber_legacy`](crate::context::broadcast_helpers::block_broadcast_subscriber_legacy)
/// (ADR-049 commit 12). See the legacy method's doc comment for the
/// full semantics. Byte-identical behavior.
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::MembershipFailed`] if the context is not broadcast.
/// - [`ContextError::MemberNotFound`] if the author is not registered.
pub async fn block_broadcast_subscriber_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    author_did: &DID,
    subscriber_did: &DID,
) -> Result<BlockResult, ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    let (result, snapshot) = {
        let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;

        require_active(&ctx.handle)?;

        let bc = ctx
            .broadcast_context
            .as_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        let result = bc.block_subscriber(author_did, subscriber_did)?;

        // Take snapshot for persistence before dropping lock (skip if
        // no persistence provider is configured).
        let snapshot = if manager_methods::has_persistence(supervisor) {
            Some(bc.to_snapshot())
        } else {
            None
        };

        // Emit block event to receive buffer.
        let block_event = ContextEvent::MemberBlocked {
            blocked_did: subscriber_did.clone(),
            author_did: author_did.clone(),
        };
        ctx.emit_event(block_event, context_id, supervisor.event_tx_ref());

        (result, snapshot)
    };
    // Lock dropped.

    // Persist broadcast state for crash recovery.
    if let Some(ref snapshot) = snapshot {
        manager_methods::persist_broadcast_snapshot(supervisor, context_id, snapshot);
    }

    supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
        .append_context_event(&context_id_bytes, "MemberBlocked", author_did.as_ref())?;
    {
        if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id) {
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            ctx.checkpoint_events_since += 1;
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// 6. unblock_broadcast_subscriber_legacy (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Unblocks a previously blocked subscriber in a broadcast context
/// (§9.16.8 — forward-only restoration).
///
/// Hoisted body of the legacy
/// [`ContextManager::unblock_broadcast_subscriber_legacy`](crate::context::broadcast_helpers::unblock_broadcast_subscriber_legacy)
/// (ADR-049 commit 12). See the legacy method's doc comment for the
/// full semantics. Byte-identical behavior.
///
/// # Errors
///
/// - [`ContextError::ContextNotRegistered`] if the context is not registered
///   or is not a broadcast context.
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::MemberNotFound`] if the author DID is not registered.
/// - [`ContextError::InvalidState`] if the subscriber is not blocked.
pub async fn unblock_broadcast_subscriber_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    author_did: &DID,
    subscriber_did: &DID,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    let snapshot = {
        let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;

        require_active(&ctx.handle)?;

        let bc = ctx
            .broadcast_context
            .as_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        let _result = bc.unblock_subscriber(author_did, subscriber_did)?;

        // Take snapshot for persistence before dropping lock.
        let snapshot = if manager_methods::has_persistence(supervisor) {
            Some(bc.to_snapshot())
        } else {
            None
        };

        // Emit unblock event to receive buffer.
        let unblock_event = ContextEvent::MemberUnblocked {
            unblocked_did: subscriber_did.clone(),
            author_did: author_did.clone(),
        };
        ctx.emit_event(unblock_event, context_id, supervisor.event_tx_ref());

        snapshot
    };
    // Lock dropped.

    // Persist broadcast state for crash recovery.
    if let Some(ref snapshot) = snapshot {
        manager_methods::persist_broadcast_snapshot(supervisor, context_id, snapshot);
    }

    supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
        .append_context_event(&context_id_bytes, "MemberUnblocked", author_did.as_ref())?;
    {
        if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id) {
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            ctx.checkpoint_events_since += 1;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 7. handle_broadcast_key_request_legacy (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Evaluates whether a subscriber's broadcast key request should be
/// granted or denied.
///
/// Hoisted body of the legacy
/// [`ContextManager::handle_broadcast_key_request_legacy`](crate::context::broadcast_helpers::handle_broadcast_key_request_legacy)
/// (ADR-049 commit 12). See the legacy method's doc comment for the
/// full semantics including the defense-in-depth `local_dids` check.
/// Byte-identical behavior.
///
/// # Errors
///
/// Returns [`ContextError::PermissionDenied`] if `author_did` is not
/// registered as a locally controlled DID.
///
/// Returns [`ContextError::MembershipFailed`] if the context is not
/// a broadcast context.
pub async fn handle_broadcast_key_request_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    author_did: &DID,
    requester_did: &DID,
) -> Result<KeyRequestDecision, ContextError> {
    // Defense-in-depth: verify the local SDK controls the author DID.
    // Transport-layer auth (section 9.16.6) is the primary gate; this prevents
    // misuse if the method is ever called from a different context.
    // Lock-free read (ADR-049 §Decision 12).
    if !supervisor.local_dids_ref().load().contains(author_did) {
        return Err(ContextError::PermissionDenied(format!(
            "author DID is not controlled by the local node: {author_did}"
        )));
    }

    let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let guard = ctx_arc.lock().await;
    let ctx = &*guard;

    let bc = ctx
        .broadcast_context
        .as_ref()
        .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

    Ok(bc.handle_key_request(author_did, requester_did))
}

// ---------------------------------------------------------------------------
// 8. broadcast_subscriber_count_legacy (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Returns the number of subscribers in a broadcast context.
///
/// Returns `None` if the context is not registered or not broadcast.
///
/// Hoisted body of the legacy
/// [`ContextManager::broadcast_subscriber_count_legacy`](crate::context::broadcast_helpers::broadcast_subscriber_count_legacy)
/// (ADR-049 commit 12). Byte-identical behavior.
pub async fn broadcast_subscriber_count_legacy(
    supervisor: &Supervisor,
    context_id: &str,
) -> Option<usize> {
    let arc = manager_methods::get_context_arc(supervisor, context_id).ok()?;
    let ctx = arc.lock().await;
    ctx.broadcast_context
        .as_ref()
        .map(BroadcastContext::subscriber_count)
}

// ---------------------------------------------------------------------------
// 9. is_broadcast_subscriber_legacy (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Returns `true` if the given DID is a subscriber in a broadcast context.
///
/// Hoisted body of the legacy
/// [`ContextManager::is_broadcast_subscriber_legacy`](crate::context::broadcast_helpers::is_broadcast_subscriber_legacy)
/// (ADR-049 commit 12). Byte-identical behavior.
pub async fn is_broadcast_subscriber_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    did: &str,
) -> bool {
    let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
        return false;
    };
    let ctx = arc.lock().await;
    ctx.broadcast_context
        .as_ref()
        .is_some_and(|bc| bc.is_subscriber(did))
}

// ---------------------------------------------------------------------------
// 10. broadcast_admission_legacy (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Returns the admission policy for a broadcast context.
///
/// Returns `None` if the context is not registered or not broadcast.
///
/// Hoisted body of the legacy
/// [`ContextManager::broadcast_admission_legacy`](crate::context::broadcast_helpers::broadcast_admission_legacy)
/// (ADR-049 commit 12). Byte-identical behavior.
pub async fn broadcast_admission_legacy(
    supervisor: &Supervisor,
    context_id: &str,
) -> Option<BroadcastAdmission> {
    let arc = manager_methods::get_context_arc(supervisor, context_id).ok()?;
    let ctx = arc.lock().await;
    ctx.broadcast_context
        .as_ref()
        .map(BroadcastContext::admission)
}
