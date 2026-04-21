//! Messaging helpers with explicit-collaborator signatures (ADR-049 §12b.1).
//!
//! # Purpose
//!
//! This module hoists six private helpers that previously lived inside
//! `crate::context::manager::messaging` and either took `&self:
//! &ContextManager` or implicitly relied on sibling modules' `pub(super)`
//! visibility. The hoist is a **pre-work** commit for the actor handler
//! body migration (commit 12b.2 of ADR-049): handler bodies cannot take
//! `&ContextManager` — they take `&ActorDeps` and `&mut PerContextState`
//! — so the helpers they call must accept explicit collaborators rather
//! than reaching through `self`.
//!
//! # Behavior preservation
//!
//! Commit 12b.1 is **behavior-preserving by construction**. Every helper
//! here produces byte-identical output for byte-identical inputs as the
//! method form it replaces. The legacy `ContextManager::send_message` /
//! `deliver_incoming` outer functions still exist (and still drive the
//! production send/receive path); they now call these free functions with
//! their own fields as arguments. The outer functions are deleted in
//! commit 12f once every handler has migrated off them.
//!
//! # Helpers hoisted
//!
//! 1. [`build_encrypted_envelope`] — access-key wrap, inner envelope
//!    sign+pad, sender-key + MLS + outer-envelope seal.
//! 2. [`enforce_send_economy`] — unified economy enforcement (cost eval,
//!    spending-UCAN AND-composition, budget deduction).
//! 3. [`build_broadcast_envelope`] — broadcast mode publish (metadata,
//!    signing payload, signature, `BroadcastContext::publish`).
//! 4. [`verify_and_unwrap`] — inner signature verification + padding
//!    strip + content integrity check + access-key unwrap (or
//!    Recovery-admin gate).
//! 5. [`deliver_plaintext_or_announcement`] — buffered/drained delivery
//!    path that detects pseudonym announcements and delivers either an
//!    announcement event or a regular `MessageReceived` event.
//! 6. [`run_buffered_post_delivery`] — post-delivery governance logic
//!    (velocity, event-log append, consequence evaluation, checkpoint
//!    increment) for buffered/drained messages (#1534).
//!
//! # State parameter
//!
//! Helpers currently take `&mut manager::PerContextState` (the legacy
//! struct). Commit 12b.2 retargets the state parameter to
//! `&mut actor::PerContextState` as handler bodies migrate. The
//! explicit-collaborator shape here is identical either way; only the
//! state-type tag changes.

use sha2::Digest;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use scp_identity::DID;
use scp_primitives::Clock;
use scp_protocol::context::ContextError;
use scp_protocol::context::broadcast::BroadcastContext;
use scp_protocol::context::builder::ContextCryptoProvider;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::crypto::access_keys::wrapping::Recipient;
use scp_protocol::crypto::access_keys::{AccessKey, WrappedContent};
use scp_protocol::crypto::sender_keys::broadcast::BroadcastEnvelope;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::envelope::inner::{InnerEnvelope, InnerEnvelopeParams, MessageType};
use scp_protocol::identity::SigningKeyId;
use scp_protocol::provenance::attach::SourceContextInfo;
use scp_protocol::trust::consequence::{ConsequenceRule, evaluate_consequence_rules};

use crate::context::builder::ContextEventLogProvider;
use crate::context::manager::{
    self, PSEUDONYM_ANNOUNCEMENT_TAG, PerContextState, PseudonymAnnouncement,
};

/// Alias for the broadcast channel used to fan out [`ContextEvent`]s to
/// external subscribers (webhook dispatcher, SDK event streams).
pub type ContextEventSender = tokio::sync::broadcast::Sender<(String, ContextEvent)>;

// ---------------------------------------------------------------------------
// 1. build_encrypted_envelope
// ---------------------------------------------------------------------------

/// Builds the encrypted envelope bytes for the send path.
///
/// Handles: access key wrapping, inner envelope creation (sign + pad),
/// and sealing (sender key + MLS + outer envelope).
///
/// # Collaborators
///
/// - `clock` — used to stamp the inner envelope `timestamp`.
/// - `crypto` — used to `seal` the inner envelope (sender key + MLS +
///   outer envelope).
///
/// # Routing
///
/// Uses [`scp_protocol::context::context_routing_id`] for the outer
/// envelope's `routing_id` per ADR-002 domain-separation. Collisions with
/// raw `SHA-256(context_id)` usages (MLS group IDs, event logs) are
/// prevented by the domain separator.
#[allow(clippy::too_many_arguments)]
pub fn build_encrypted_envelope(
    clock: &Arc<dyn Clock>,
    crypto: &Arc<dyn ContextCryptoProvider>,
    context_id: &str,
    sender_did: &DID,
    payload: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
    recipients_data: &std::collections::HashMap<String, AccessKey>,
    sequence: u64,
    source_provenance: Option<&SourceContextInfo>,
) -> Result<Vec<u8>, ContextError> {
    let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);
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
    let timestamp = clock.now_millis();
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
    let routing_id = scp_protocol::context::context_routing_id(context_id);
    crypto.seal(
        &context_id_bytes,
        &inner,
        &routing_id,
        manager::messaging::DEFAULT_BLOB_TTL_SECS,
    )
}

// ---------------------------------------------------------------------------
// 2. enforce_send_economy
// ---------------------------------------------------------------------------

/// Enforces economic policy for message sends (#1537, #1593).
///
/// Unified economy enforcement: evaluates cost, checks spending UCAN
/// AND-composition (spec §19.5), and records spend against the sender's
/// budget. No auto-grant — budget must be explicitly approved via
/// `ApproveSpend` governance action.
///
/// Returns the deducted cost (if any) so that the caller can carry it in
/// an `EconomyTicket` and drain all refundable economic state together via
/// `rollback_economy_ticket` on failure (F4).
///
/// # Collaborators
///
/// - `clock` — used for UCAN expiry validation inside
///   [`manager::economy::enforce_economy`]. Passed as `&dyn Clock` to match
///   the trait-object shape the downstream call expects.
/// - `key_resolver` — resolves the actor's UCAN signing key; same shape
///   as the resolver used for governance vote verification.
pub fn enforce_send_economy(
    ctx: &mut PerContextState,
    sender_did: &DID,
    now: u64,
    spending_ucan: Option<&UcanToken>,
    context_id: &str,
    clock: &dyn Clock,
    key_resolver: &KeyResolver,
) -> Result<Option<scp_protocol::economy::types::Amount>, ContextError> {
    let pricing_default =
        scp_protocol::economy::antispam::ContextMessagePricingConfig::spec_default();
    // Compute member_count first so it does not race the upcoming split
    // borrow of `ctx.governance`.
    let member_count = ctx.membership.count();
    // C1 (PR #1606): split-borrow `ctx.governance` so that the mutable
    // budget/nonce borrows and the immutable velocity/policy/revocation
    // borrows can coexist in a single `EnforceEconomyRequest`. Disjoint
    // fields are borrow-checked individually.
    let governance = &mut ctx.governance;
    let pricing = governance
        .message_pricing
        .as_ref()
        .unwrap_or(&pricing_default);
    manager::economy::enforce_economy(manager::economy::EnforceEconomyRequest {
        economic_policy: governance.economic_policy.as_ref(),
        budget_tracker: &mut governance.budget_tracker,
        velocity_tracker: &governance.velocity_tracker,
        member_count,
        action_type: scp_protocol::economy::types::PaidActionType::MessageSend,
        actor_did: sender_did,
        now,
        spending_ucan,
        action_label: "messages:write",
        context_id,
        clock,
        pricing,
        nonce_tracker: &mut governance.spending_nonce_tracker,
        revoked_spending_ucan_cids: &governance.revoked_spending_ucan_cids,
        key_resolver,
    })
}

// ---------------------------------------------------------------------------
// 3. build_broadcast_envelope
// ---------------------------------------------------------------------------

/// Builds a broadcast envelope for the send path.
///
/// Handles signing payload construction, signature generation, and
/// [`BroadcastContext::publish`].
///
/// # Collaborators
///
/// - `clock` — used to stamp the broadcast envelope `timestamp`.
pub fn build_broadcast_envelope(
    clock: &dyn Clock,
    bc: &mut BroadcastContext,
    sender_did: &DID,
    payload: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<BroadcastEnvelope, ContextError> {
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
    )
    .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
    let signature = ed25519_dalek::Signer::sign(signing_key, &signing_payload);
    bc.publish(sender_did, payload, timestamp, signature, &nonce, None)
}

// ---------------------------------------------------------------------------
// 4. verify_and_unwrap
// ---------------------------------------------------------------------------

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
///
/// # Collaborators
///
/// - `key_resolver` — resolves the sender's Ed25519 verifying key so the
///   inner signature can be checked. Fail-closed: an unresolvable DID
///   yields `ContextError::CryptoFailed`.
#[allow(clippy::too_many_arguments)]
pub fn verify_and_unwrap(
    key_resolver: &KeyResolver,
    inner: &InnerEnvelope,
    sender_did: &str,
    context_id: &str,
    local_member_did: &str,
    access_key: &AccessKey,
    sender_is_admin: bool,
) -> Result<Vec<u8>, ContextError> {
    // Verify inner signature (fail-closed: reject if key cannot be resolved).
    let public_key = (key_resolver)(&DID(sender_did.to_owned())).ok_or_else(|| {
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
    let wrapped: WrappedContent = rmp_serde::from_slice(&stripped)
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

// ---------------------------------------------------------------------------
// 5. deliver_plaintext_or_announcement
// ---------------------------------------------------------------------------

/// Delivers a single plaintext to the receive buffer, checking if it is a
/// pseudonym announcement first. If it is a valid announcement from the
/// authenticated sender, updates the pseudonym registry and emits a
/// `PseudonymAnnounced` event instead of `MessageReceived`.
///
/// Used by all buffered/drained delivery paths (`drain_timed_out`,
/// `drain_consecutive`, buffer overflow) to ensure announcements received
/// out of order are still handled correctly.
///
/// Returns the event-log event name for the delivered message, or `None`
/// when the message was silently dropped (e.g. forged announcement).
/// Callers use the return value to drive post-delivery logic (velocity,
/// event log, consequences, checkpoint).
pub fn deliver_plaintext_or_announcement(
    ctx: &mut PerContextState,
    sender_did: &str,
    plaintext: &[u8],
    context_id: &str,
    event_tx: Option<&ContextEventSender>,
) -> Option<&'static str> {
    // KNOWN LIMITATION (§9.10.4 vs §9.10.4.A): Spec says receivers should verify
    // the pseudonym-to-DID mapping, but the privacy model (pseudonym_secret from
    // private key) makes independent verification impossible. We trust MLS-
    // authenticated senders to honestly announce their pseudonyms. A malicious
    // member can only misdirect their own message copies.
    if let Ok(announcement) = rmp_serde::from_slice::<PseudonymAnnouncement>(plaintext)
        && announcement.tag == PSEUDONYM_ANNOUNCEMENT_TAG
    {
        if announcement.member_did != sender_did {
            tracing::warn!(
                context_id,
                sender_did,
                claimed_did = %announcement.member_did,
                "buffered pseudonym announcement sender mismatch — dropping"
            );
            return None; // Drop forged announcement, don't deliver as message
        }
        let did = DID(announcement.member_did.clone());
        ctx.pseudonym_registry
            .insert(did.clone(), announcement.pseudonym);
        let event = ContextEvent::PseudonymAnnounced {
            member_did: did,
            pseudonym: announcement.pseudonym,
        };
        ctx.emit_event(event, context_id, event_tx);
        tracing::debug!(
            context_id,
            sender_did,
            "processed buffered pseudonym announcement"
        );
        return Some("PseudonymAnnounced");
    }
    let event = ContextEvent::MessageReceived {
        sender_did: DID(sender_did.to_owned()),
        payload: plaintext.to_vec(),
    };
    ctx.emit_event(event, context_id, event_tx);
    Some("MessageReceived")
}

// ---------------------------------------------------------------------------
// 6. run_buffered_post_delivery
// ---------------------------------------------------------------------------

/// Runs post-delivery governance logic for a single buffered/drained message.
///
/// This ensures that messages delivered via reorder-buffer drain (timeout,
/// consecutive fill, overflow) receive the same velocity tracking, event-log
/// append, consequence evaluation, and checkpoint increment as messages
/// delivered directly through `deliver_message_and_drain_buffered`.
///
/// Bug fix (#1534): previously, all buffered delivery paths skipped these
/// steps, allowing a malicious sender to evade rate limiting and consequence
/// enforcement by exploiting out-of-order delivery.
#[allow(clippy::too_many_arguments)] // FFI threading of event_tx
pub fn run_buffered_post_delivery(
    ctx: &mut PerContextState,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    sender_did: &str,
    event_name: &str,
    clock: &dyn Clock,
    event_log: &dyn ContextEventLogProvider,
    event_tx: Option<&ContextEventSender>,
) {
    let now = clock.now_secs();

    // Velocity tracking — always record for buffered messages. Buffered
    // messages arrived via the receive path; we cannot determine whether the
    // sender is local (the info isn't stored in BufferedMessage). Recording
    // unconditionally is the safe default: a minor double-count on single-node
    // self-loops is preferable to a missed count that bypasses rate limiting.
    ctx.governance
        .velocity_tracker
        .record_message(&DID(sender_did.to_owned()), now);

    // Durable event-log append — mirrors the direct delivery path.
    if let Err(e) = event_log.append_context_event(context_id_bytes, event_name, sender_did) {
        tracing::warn!(
            context_id,
            sender_did,
            event_name,
            "failed to append buffered event to event log: {e}"
        );
    }

    // Consequence evaluation — same rules as the direct path.
    let consequence_rules: Vec<ConsequenceRule> = ctx.governance.consequence_rules.clone();
    if !consequence_rules.is_empty() {
        let events = manager::governance::event_log_entries_for_consequences(
            ctx, context_id, now, event_log,
        );
        let triggered = evaluate_consequence_rules(&consequence_rules, &events, sender_did, now);
        let member_did = DID(sender_did.to_owned());
        manager::governance::enforce_triggered_consequences(
            ctx,
            &manager::governance::EnforceConsequencesCtx {
                context_id,
                member_did: &member_did,
                now,
                triggered: &triggered,
                rules: &consequence_rules,
                clock,
                event_log,
                event_tx,
            },
        );
    }

    // Checkpoint tracking — increment so thresholds stay accurate.
    ctx.checkpoint_events_since += 1;
}
