//! Messaging helpers with explicit-collaborator signatures (ADR-049 §12b.1 / §12c.1).
//!
//! # Purpose
//!
//! This module hoists the messaging-domain helpers and top-level send /
//! receive methods that previously lived inside
//! `crate::context::manager::messaging`. Commit 12b.1 hoisted six pure
//! [`PerContextState`]-scoped helpers. Commit 12c.1 extends the hoist to
//! the two top-level messaging methods [`send_message`] and
//! [`deliver_incoming`]. The hoist is a **pre-work** commit for the actor
//! handler body migration (commit 12c.2 of ADR-049): handler bodies
//! cannot take `&ContextManager` — they take `&ActorDeps` and
//! `&mut PerContextState` — so the helpers they call must accept
//! explicit collaborators rather than reaching through `self`.
//!
//! # Behavior preservation
//!
//! Both commits are **behavior-preserving by construction**. Every helper
//! here produces byte-identical output for byte-identical inputs as the
//! method form it replaces. The legacy `ContextManager::send_message` /
//! `deliver_incoming` outer methods still exist (and still drive the
//! production send/receive path); they are now one-line forwarders that
//! call [`send_message`] / [`deliver_incoming`] with their own fields as
//! arguments. The outer methods are deleted in commit 12f once every
//! handler has migrated off them.
//!
//! # 12c.1 hoist scope — messaging-internal transitives NOT hoisted
//!
//! Commit 12c.1 hoists only the two top-level methods. The
//! messaging-internal private helpers
//! [`ContextManager::encrypt_and_send`](crate::context::manager::ContextManager::encrypt_and_send),
//! [`ContextManager::authorize_send_payment`](crate::context::manager::ContextManager::authorize_send_payment),
//! [`ContextManager::capture_send_payment`](crate::context::manager::ContextManager::capture_send_payment),
//! [`ContextManager::finalize_send`](crate::context::manager::ContextManager::finalize_send),
//! [`ContextManager::decrypt_and_dispatch`](crate::context::manager::ContextManager::decrypt_and_dispatch),
//! [`ContextManager::validate_and_drain_timeouts`](crate::context::manager::ContextManager::validate_and_drain_timeouts),
//! [`ContextManager::buffer_ahead_message`](crate::context::manager::ContextManager::buffer_ahead_message),
//! and
//! [`ContextManager::deliver_message_and_drain_buffered`](crate::context::manager::ContextManager::deliver_message_and_drain_buffered)
//! remain as inherent methods on `ContextManager` for this commit — the
//! hoisted [`send_message`] / [`deliver_incoming`] call them via the
//! `mgr` parameter. They are themselves hoisted in a follow-up step of
//! 12c.1 (continuation) and then deleted alongside the outer shim in
//! commit 12f.
//!
//! # Helpers hoisted
//!
//! 1. [`build_encrypted_envelope`] — access-key wrap, inner envelope
//!    sign+pad, sender-key + MLS + outer-envelope seal. (12b.1)
//! 2. [`enforce_send_economy`] — unified economy enforcement (cost eval,
//!    spending-UCAN AND-composition, budget deduction). (12b.1)
//! 3. [`build_broadcast_envelope`] — broadcast mode publish (metadata,
//!    signing payload, signature, `BroadcastContext::publish`). (12b.1)
//! 4. [`verify_and_unwrap`] — inner signature verification + padding
//!    strip + content integrity check + access-key unwrap (or
//!    Recovery-admin gate). (12b.1)
//! 5. [`deliver_plaintext_or_announcement`] — buffered/drained delivery
//!    path that detects pseudonym announcements and delivers either an
//!    announcement event or a regular `MessageReceived` event. (12b.1)
//! 6. [`run_buffered_post_delivery`] — post-delivery governance logic
//!    (velocity, event-log append, consequence evaluation, checkpoint
//!    increment) for buffered/drained messages (#1534). (12b.1)
//! 7. [`send_message`] — top-level send path: Phase 1 (under-lock
//!    capability + economy + envelope construction), payment
//!    authorization, Phase 2 (off-lock encrypt + transport fan-out),
//!    Phase 3 (payment capture + finalize). (12c.1)
//! 8. [`deliver_incoming`] — top-level receive path: decrypt + dispatch
//!    management messages, verify + unwrap, anti-replay + reorder buffer
//!    management, in-order delivery or gap-buffering. (12c.1)
//!
//! # State parameter
//!
//! Leaf helpers take `&mut manager::PerContextState` (the legacy
//! struct). Commit 12b.2 retargets the state parameter to
//! `&mut actor::PerContextState` as handler bodies migrate. The
//! explicit-collaborator shape here is identical either way; only the
//! state-type tag changes.

use std::sync::Arc;

use sha2::Digest;
use subtle::ConstantTimeEq;

use scp_identity::DID;
use scp_primitives::Clock;
use scp_protocol::context::ContextError;
use scp_protocol::context::broadcast::BroadcastContext;
use scp_protocol::context::builder::ContextCryptoProvider;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::roles::Capability;
use scp_protocol::crypto::access_keys::wrapping::Recipient;
use scp_protocol::crypto::access_keys::{AccessKey, WrappedContent};
use scp_protocol::crypto::sender_keys::broadcast::BroadcastEnvelope;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::envelope::inner::{InnerEnvelope, InnerEnvelopeParams, MessageType};
use scp_protocol::envelope::validation::SequenceCheck;
use scp_protocol::identity::SigningKeyId;
use scp_protocol::provenance::attach::SourceContextInfo;
use scp_protocol::trust::consequence::{ConsequenceRule, evaluate_consequence_rules};

use crate::context::ContextHandle;
use crate::context::builder::ContextEventLogProvider;
use crate::context::manager::{
    self, ContextManager, PSEUDONYM_ANNOUNCEMENT_TAG, PerContextState, PseudonymAnnouncement,
};
use crate::context::supervisor::Supervisor;

/// Shared expectation message for `Supervisor::attached_context_manager()`
/// and `Supervisor::*_ref()` accessors inside helpers. The attach-time
/// contract (see
/// [`Supervisor::attach_context_manager`](crate::context::supervisor::Supervisor::attach_context_manager))
/// installs the manager (and lifts every provider slot) before any FFI
/// caller or test can invoke a helper, so unwrap is panic-only under a
/// contract violation.
const ATTACHED_EXPECT: &str = "messaging_helpers: Supervisor must be fully attached before helper invocation \
     (set by Supervisor::attach_context_manager during bridge construction)";

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

// ---------------------------------------------------------------------------
// 7. send_message (top-level, hoisted in commit 12c.1)
// ---------------------------------------------------------------------------

/// Sends a message within a context (hoisted body of the legacy
/// [`ContextManager::send_message`]). Orchestrates the full 3-phase send
/// pipeline:
///
/// 1. **Under-lock Phase 1**: state check, commit-fault gate, capability
///    check, hard-rate-limit consume, velocity record, economy
///    enforcement, broadcast-envelope build (broadcast mode) OR sequence
///    assignment + routing-ID fan-out list (encrypted mode), producing
///    an [`EconomyTicket`](crate::context::manager::economy::EconomyTicket)
///    carrying all refundable state.
/// 2. **Off-lock Phase 2**: payment authorization (escrow hold), then
///    encrypt and transport fan-out. On any failure, voids the escrow
///    hold, drains the `EconomyTicket`, and rolls back the sequence
///    number (if not broadcast).
/// 3. **Phase 3**: commit the `EconomyTicket` (marks consumed so the
///    Drop guard stays quiet), capture the payment, and `finalize_send`
///    (event-log append, consequence evaluation, participation-record
///    update, checkpoint tracking, persistence snapshot).
///
/// # Collaborators
///
/// - `mgr` — manager reference used to reach still-on-manager helpers
///   (`lock_context`, `relock_context`, `authorize_send_payment`,
///   `encrypt_and_send`, `capture_send_payment`, `finalize_send`,
///   `void_paid_action`, and the economy-ticket rollback helpers). The
///   messaging-internal private methods remain on `ContextManager` in
///   commit 12c.1; they are hoisted in a 12c.1 continuation step and
///   finally deleted in commit 12f alongside this outer shim.
/// - `clock` — wall-clock source used for the `now_secs` stamp in the
///   Phase 1 rate-limit / velocity / economy branch. Passed explicitly
///   so the 12b.1 helpers ([`enforce_send_economy`]) receive the same
///   clock as the surrounding code — a divergence here would race on
///   the rate-limit window boundary.
/// - `key_resolver` — forwarded into [`enforce_send_economy`] for
///   UCAN signature verification on the spending-UCAN path.
///
/// # Behavior preservation
///
/// Byte-identical to the legacy method form in commit 12b.1. The
/// forwarder in `ContextManager::send_message` calls this function
/// with `self` as `mgr` and `&self.clock` / `&self.key_resolver` as the
/// explicit collaborators.
#[allow(clippy::too_many_lines)] // Matches legacy method shape; cannot split further without fragmenting the Phase 1 lock scope.
#[allow(clippy::too_many_arguments)] // Hoisted body retains the legacy signature plus explicit collaborators per task spec.
#[allow(clippy::significant_drop_tightening)] // Legacy body held guards across await points deliberately — narrowing changes lock-ordering semantics.
pub async fn send_message(
    supervisor: &Supervisor,
    clock: &Arc<dyn Clock>,
    key_resolver: &KeyResolver,
    handle: &ContextHandle,
    sender_did: &DID,
    payload: &[u8],
    signing_key: Option<&ed25519_dalek::SigningKey>,
    source_provenance: Option<&SourceContextInfo>,
    spending_ucan: Option<&UcanToken>,
) -> Result<(), ContextError> {
    let mgr = supervisor
        .attached_context_manager()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = scp_protocol::context::context_id_bytes(&context_id);
    // Routing ID computation is deferred to Phase 1 (under lock) where
    // the context mode and pseudonym registry are available.
    let (
        broadcast_envelope,
        recipients_data,
        sequence,
        is_broadcast,
        ticket,
        ctx_gen,
        send_routing_ids,
    ) = {
        let (mut guard, ctx_gen) = mgr
            .lock_context(&context_id)
            .await
            .map_err(|_| ContextError::ContextNotRegistered(context_id.clone()))?;
        let ctx = &mut *guard;
        manager::require_active(&ctx.handle)?;
        // N3: Fail-close on commit fault — if a prior governance
        // mutation's MLS Commit failed to broadcast and exhausted
        // retries, messages encrypted under the divergent epoch may
        // be undecryptable by members who never received the Commit.
        ContextManager::check_commit_fault(ctx)?;
        // H7: check capability BEFORE budget deduction so a capability
        // failure doesn't leak budget. The suspension-aware
        // member_has_capability check handles both role-based and
        // suspension-based denial.
        if ctx.broadcast_context.is_none()
            && !ctx
                .role_state
                .member_has_capability(sender_did.as_ref(), &Capability::MessagesWrite)
        {
            let is_suspended = ctx
                .role_state
                .suspended_capabilities
                .get(sender_did.as_ref())
                .is_some_and(|s| s.contains(&Capability::MessagesWrite));
            let msg = if is_suspended {
                format!("member {sender_did} write access has been revoked")
            } else {
                format!("member {sender_did} does not have messages:write capability")
            };
            return Err(ContextError::PermissionDenied(msg));
        }
        // Defense-in-depth (Matrix Synapse–style hard rate limit): consume
        // a token from the per-sender bucket before any pricing logic.
        // This bounds inbound load even when no economic policy or budget
        // is configured. On any subsequent failure we refund the token so
        // a rejected attempt does not consume bucket capacity.
        let now_secs = clock.now_secs();
        if !ctx
            .governance
            .hard_rate_limit
            .try_consume(sender_did, now_secs)
        {
            return Err(ContextError::RateLimited {
                resource: "send".to_owned(),
                message: "hard rate limit exceeded for sender".to_owned(),
            });
        }
        // M4: record velocity BEFORE economy enforcement so the current
        // message is included in the velocity metric used for pricing.
        // F5: capture the rollback token so we can refund THIS entry
        // specifically (not race concurrent senders on "the last one").
        let velocity_token = ctx
            .governance
            .velocity_tracker
            .record_message(sender_did, now_secs);

        let deducted_cost = match enforce_send_economy(
            ctx,
            sender_did,
            now_secs,
            spending_ucan,
            &context_id,
            &**clock,
            key_resolver,
        ) {
            Ok(cost) => cost,
            Err(e) => {
                // Roll back both: the velocity increment recorded above
                // and the hard-rate-limit token. A rejected message must
                // not permanently penalize the sender on either axis.
                // No EconomyTicket exists yet at this point — rollback
                // inline under the still-held lock.
                ctx.governance
                    .velocity_tracker
                    .rollback(sender_did, velocity_token);
                ctx.governance.hard_rate_limit.refund(sender_did);
                return Err(e);
            }
        };
        // F4: wrap the Phase 1 economy state in an EconomyTicket so
        // every downstream error branch is forced to consume it.
        // Dropping without commit/rollback is a compile-time warning
        // (`#[must_use]`) + debug-assert at runtime.
        let ticket = manager::economy::EconomyTicket {
            actor_did: sender_did.clone(),
            deducted_cost,
            velocity_token,
            needs_hard_rate_limit_refund: true,
            consumed: false,
        };
        if let Some(ref mut bc) = ctx.broadcast_context {
            let Some(sk) = signing_key else {
                // Phase 1 failed after ticket creation — drain it.
                // Use inline variant: we already hold the per-context lock.
                manager::economy::rollback_economy_ticket_inline(ctx, ticket);
                return Err(ContextError::CryptoFailed(
                    "signing key required for broadcast publish".into(),
                ));
            };
            let env = match build_broadcast_envelope(&**clock, bc, sender_did, payload, sk) {
                Ok(env) => env,
                Err(e) => {
                    // Use inline variant: we already hold the per-context lock.
                    manager::economy::rollback_economy_ticket_inline(ctx, ticket);
                    return Err(e);
                }
            };
            // Broadcast: use plain SHA-256(context_id) per spec §5.14.
            let broadcast_rid = scp_protocol::context::broadcast_routing_id(&context_id);
            (
                Some(env),
                std::collections::HashMap::new(),
                0,
                true,
                ticket,
                ctx_gen,
                vec![broadcast_rid],
            )
        } else {
            // Capability already checked above (H7: before budget deduction).
            // Assign sequence under lock — SequenceTracker rejects duplicates.
            let Some(seq) = ctx.membership.next_sequence_number(sender_did) else {
                // Use inline variant: we already hold the per-context lock.
                manager::economy::rollback_economy_ticket_inline(ctx, ticket);
                return Err(ContextError::MemberNotFound(format!(
                    "cannot assign sequence: {sender_did} is not a member"
                )));
            };
            // §9.10.4: collect pseudonym routing IDs for fan-out.
            // For encrypted contexts with known pseudonyms, send to each
            // member's pseudonym. Always include the shared routing ID as
            // fallback for members whose pseudonym is not yet known.
            //
            // KNOWN LIMITATION (§9.10.4): Fan-out sends the SAME MLS ciphertext to all
            // routing IDs. A relay can correlate pseudonyms by observing identical blobs.
            // Per-recipient re-encryption (different nonce per blob) would fix this but
            // increases bandwidth by O(N). Acceptable until relay-blinding is implemented.
            let mut routing_ids: Vec<[u8; 32]> = ctx.pseudonym_registry.values().copied().collect();
            let shared_rid = scp_protocol::context::context_routing_id(&context_id);
            // Always include the shared routing ID for backward compat /
            // members who haven't announced a pseudonym yet. Duplicates
            // in the fan-out are harmless (same blob to same routing ID
            // is idempotent at the relay).
            routing_ids.push(shared_rid);
            (
                None,
                ctx.access.access_key_store.get_all(&context_id),
                seq,
                false,
                ticket,
                ctx_gen,
                routing_ids,
            )
        }
    };
    // Payment flow (#1537): escrow pattern — authorize (hold) before the
    // action, complete (capture) after success, void + rollback on failure.
    let auth = match mgr.authorize_send_payment(&context_id, sender_did).await {
        Ok(auth) => auth,
        Err(e) => {
            // Authorization failure — roll back the ticket. The sequence
            // number rollback is also needed because Phase 1 already
            // incremented it for non-broadcast.
            manager::economy::rollback_economy_ticket(mgr, &context_id, ticket, &ctx_gen).await;
            if !is_broadcast {
                if let Ok(mut guard) = mgr.relock_context(&ctx_gen).await {
                    let ctx = &mut *guard;
                    ctx.membership.rollback_sequence_number(sender_did);
                } else {
                    tracing::warn!(
                        context_id = %context_id,
                        "send_message: generation mismatch on payment auth rollback — \
                         sequence number rollback skipped"
                    );
                }
            }
            return Err(e);
        }
    };

    // Phase 2: encrypt + send (no lock held).
    // §9.10.4: fan-out — send to all collected routing IDs.
    let phase2_result = mgr.encrypt_and_send(
        broadcast_envelope,
        signing_key,
        &context_id,
        sender_did,
        payload,
        &recipients_data,
        sequence,
        source_provenance,
        &send_routing_ids,
    );
    if let Err(e) = phase2_result {
        // Void the escrow hold and roll back the full ticket (budget,
        // velocity, hard-rate-limit) on send failure. F4: before this
        // patch the outer rollback only touched the budget, silently
        // leaking the velocity entry and the hard-rate-limit token.
        if let Some(a) = auth {
            mgr.void_paid_action(a, &context_id).await;
        }
        manager::economy::rollback_economy_ticket(mgr, &context_id, ticket, &ctx_gen).await;
        if !is_broadcast {
            if let Ok(mut guard) = mgr.relock_context(&ctx_gen).await {
                let ctx = &mut *guard;
                ctx.membership.rollback_sequence_number(sender_did);
            } else {
                tracing::warn!(
                    context_id = %context_id,
                    "send_message: generation mismatch on send failure rollback — \
                     sequence number rollback skipped"
                );
            }
        }
        return Err(e);
    }

    // Phase 3: capture the escrow hold after successful send. Consume
    // the ticket — commit returns the deducted cost for the capture step
    // and marks the ticket as committed so the Drop guard stays quiet.
    let deducted_cost = manager::economy::commit_economy_ticket(ticket);
    mgr.capture_send_payment(auth, sender_did, &context_id, deducted_cost)
        .await;

    mgr.finalize_send(
        &context_id,
        &context_id_bytes,
        sender_did,
        sequence,
        payload,
        signing_key,
        &ctx_gen,
    )
    .await
}

// ---------------------------------------------------------------------------
// 8. deliver_incoming (top-level, hoisted in commit 12c.1)
// ---------------------------------------------------------------------------

/// Delivers an incoming encrypted message from the relay to a context
/// (hoisted body of the legacy [`ContextManager::deliver_incoming`]).
///
/// Opens the received envelope through the full receive pipeline,
/// verifies the inner signature, validates anti-replay sequence numbers,
/// unwraps content access keys, and emits a `MessageReceived` event.
///
/// Out-of-order messages (§9.8.5) are buffered in a per-sender reorder
/// buffer. When a gap fills, all consecutive buffered messages are
/// delivered in order. If a gap persists past the timeout, buffered
/// messages are force-delivered with a suppression alert.
///
/// Returns `Ok(Some((plaintext, sender_did)))` when a message is
/// delivered immediately, `Ok(None)` when the message is buffered (gap
/// detected) or was a Commit/Proposal/management message, or `Err` on
/// failure.
///
/// # Collaborators
///
/// - `mgr` — manager reference used to reach still-on-manager helpers
///   (`get_context_arc`, `decrypt_and_dispatch`,
///   `validate_and_drain_timeouts`, `deliver_message_and_drain_buffered`,
///   `buffer_ahead_message`). These are hoisted in a 12c.1 continuation
///   step and deleted in commit 12f alongside this outer shim.
/// - `clock` — wall-clock source for the `now_millis` stamp used by
///   anti-replay / reorder-buffer logic. Passed explicitly so the
///   hoisted verify + unwrap path receives the same clock instance as
///   the downstream manager calls.
/// - `key_resolver` — forwarded into [`verify_and_unwrap`] to resolve
///   the sender's Ed25519 verifying key for inner-signature verification.
///
/// # Behavior preservation
///
/// Byte-identical to the legacy method form in commit 12b.1. The
/// forwarder in `ContextManager::deliver_incoming` calls this function
/// with `self` as `mgr` and `&self.clock` / `&self.key_resolver` as the
/// explicit collaborators.
#[allow(clippy::significant_drop_tightening)]
// Legacy body held guards across await points deliberately — narrowing changes lock-ordering semantics.
#[allow(
    clippy::too_many_lines,
    reason = "verbatim hoist of the legacy receive path — splitting would \
              fragment the three-phase decrypt/verify/deliver pipeline"
)]
pub async fn deliver_incoming(
    supervisor: &Supervisor,
    clock: &Arc<dyn Clock>,
    key_resolver: &KeyResolver,
    context_id: &str,
    encrypted_blob: &[u8],
) -> Result<Option<(Vec<u8>, String)>, ContextError> {
    let mgr = supervisor
        .attached_context_manager()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);

    // Phase 1: state check + read local member DID + access key.
    // Read local_dids FIRST (RwLock read, low contention) to avoid
    // nested lock ordering issues with the contexts Mutex.
    let local_dids = supervisor
        .local_dids_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
        .read()
        .await;
    let (local_member_did, access_key) = {
        let ctx_arc = mgr
            .get_context_arc_pub(context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;
        manager::require_active(&ctx.handle)?;
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
    let Some(opened_envelope) =
        mgr.decrypt_and_dispatch(context_id, &context_id_bytes, encrypted_blob)?
    else {
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
    let sender_is_admin = if inner.message_type == MessageType::Recovery {
        if let Ok(ctx_arc) = mgr.get_context_arc_pub(context_id) {
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            ctx.role_state
                .member_has_capability(&sender_did, &Capability::ContextClose)
        } else {
            false
        }
    } else {
        false // irrelevant for non-Recovery messages
    };

    let ak = access_key.ok_or_else(|| {
        ContextError::CryptoFailed(format!(
            "no access key for {local_member_did} in context {context_id}"
        ))
    })?;
    let plaintext = verify_and_unwrap(
        key_resolver,
        &inner,
        &sender_did,
        context_id,
        &local_member_did,
        &ak,
        sender_is_admin,
    )?;

    // Anti-replay + reorder buffer (§9.8.2, §9.8.5).
    // Now safe to inspect SequenceTracker — the envelope is authenticated.
    let now_ms = clock.now_millis();
    let sequence_check = mgr
        .validate_and_drain_timeouts(context_id, &inner, now_ms)
        .await?;

    // A locally-controlled sender was already counted on the send path;
    // skip velocity re-recording to prevent double-counting on single-node setups.
    let is_local_sender = sender_did == local_member_did;

    match sequence_check {
        SequenceCheck::Expected => {
            // Message is in order — deliver immediately.
            // Bug fix (#1534): `deliver_message_and_drain_buffered` returns
            // `true` when the message was consumed as a pseudonym announcement
            // (internal protocol message). Announcements must NOT be forwarded
            // to FFI callers as regular user messages.
            let consumed_as_announcement = mgr
                .deliver_message_and_drain_buffered(
                    context_id,
                    &context_id_bytes,
                    &sender_did,
                    &inner,
                    &plaintext,
                    is_local_sender,
                )
                .await?;
            if consumed_as_announcement {
                Ok(None)
            } else {
                Ok(Some((plaintext, sender_did)))
            }
        }
        SequenceCheck::Ahead { expected: _ } => {
            // Message is ahead of expected — buffer it (§9.8.5).
            mgr.buffer_ahead_message(context_id, &inner, &sender_did, &plaintext, now_ms)
                .await?;
            Ok(None)
        }
    }
}

// ===========================================================================
// 12c.1b hoist — 8 messaging transitives previously on ContextManager.
// ===========================================================================
//
// The free-function forms below mirror the legacy inherent-method bodies
// byte-for-byte; only the `self.X` projections change to `mgr.X_ref()`
// accessor calls or `mgr.X()` pub(crate) methods. The legacy methods
// on `ContextManager` in `manager/messaging.rs` are now one-line
// forwarders so existing callers (tests, hoisted top-level methods,
// manager/tests integration) continue to compile unchanged.
//
// The pipeline-wiring tests (`crates/scp-testing/tests/integration/
// pipeline_wiring.rs`) extract function bodies by first occurrence of
// `fn <name>(` in `MANAGER_SRC`. `MANAGER_SRC` concatenates
// `messaging_helpers.rs` BEFORE `manager/messaging.rs`, so the hoisted
// free-function bodies here win the brace-match lookup and the literal
// call-text assertions (`.send_message(`, `tv.validate`,
// `create_checkpoint_if_due`, etc.) are preserved.

// ---------------------------------------------------------------------------
// 9. encrypt_and_send (hoisted in commit 12c.1b)
// ---------------------------------------------------------------------------

/// Encrypts the payload and sends it via transport (Phase 2 of
/// [`send_message`]).
///
/// For pseudonym routing (§9.10.4), `routing_ids` may contain multiple
/// targets: each member's pseudonym plus the shared context routing ID
/// as a fallback. The encrypted blob is computed once and sent to each
/// routing ID.
///
/// # Collaborators
///
/// - `mgr` — read access to `clock_ref()`, `crypto_ref()`,
///   `transport_ref()`. The clock stamps the inner envelope timestamp
///   (inside [`build_encrypted_envelope`]), the crypto provider seals
///   the envelope, and the transport provider performs fan-out sends.
///
/// # Behavior preservation
///
/// Byte-identical to the legacy
/// [`ContextManager::encrypt_and_send`](crate::context::manager::ContextManager::encrypt_and_send)
/// method form. The `self.transport.send_message(rid, &encrypted)`
/// call becomes `supervisor.transport_ref().ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?.send_message(rid, &encrypted)` —
/// the literal `.send_message(` call-text is preserved so pipeline
/// wiring assertions continue to match.
#[allow(clippy::too_many_arguments)] // Retains legacy method signature plus explicit `mgr` param per ADR-049 §12c.1b.
pub fn encrypt_and_send(
    supervisor: &Supervisor,
    broadcast_envelope: Option<BroadcastEnvelope>,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    context_id: &str,
    sender_did: &DID,
    payload: &[u8],
    recipients_data: &std::collections::HashMap<String, AccessKey>,
    sequence: u64,
    source_provenance: Option<&SourceContextInfo>,
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
            supervisor
                .clock_ref()
                .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
            supervisor
                .crypto_ref()
                .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
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
        match supervisor
            .transport_ref()
            .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
            .send_message(rid, &encrypted)
        {
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
        return Err(last_err
            .unwrap_or_else(|| ContextError::TransportFailed("all fan-out sends failed".into())));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 10. authorize_send_payment (hoisted in commit 12c.1b)
// ---------------------------------------------------------------------------

/// Authorizes escrow for send payment (Phase 1.5 of [`send_message`]).
///
/// On failure, the caller is responsible for draining the `EconomyTicket`
/// via `rollback_economy_ticket`. This helper MUST NOT roll back any
/// economic state itself — doing so from here would double-refund the
/// budget when the caller subsequently drains the ticket (F4).
/// Returns the authorization token (if payment is required) for later
/// capture or void.
///
/// # Collaborators
///
/// - `mgr` — delegates to
///   [`ContextManager::authorize_paid_action`](crate::context::manager::ContextManager::authorize_paid_action)
///   (pub(crate)), which owns the economy-policy lookup and escrow
///   reservation.
///
/// # Behavior preservation
///
/// Byte-identical to the legacy method form.
pub async fn authorize_send_payment(
    supervisor: &Supervisor,
    context_id: &str,
    sender_did: &DID,
) -> Result<Option<manager::economy::PaidActionAuthorization>, ContextError> {
    let mgr = supervisor
        .attached_context_manager()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    mgr.authorize_paid_action(
        scp_protocol::economy::types::PaidActionType::MessageSend,
        sender_did,
        context_id,
    )
    .await
}

// ---------------------------------------------------------------------------
// 11. capture_send_payment (hoisted in commit 12c.1b)
// ---------------------------------------------------------------------------

/// Captures the escrow hold after a successful send (Phase 3 of
/// [`send_message`]).
///
/// Best-effort: if capture fails, logs a warning but does NOT roll back
/// the budget and does NOT fail the send. The message was already
/// delivered — the service was rendered, so the budget deduction stands.
/// Rolling back on capture failure would let senders consume the service
/// for free whenever the payment adapter is flaky (H8).
///
/// On failure a `PaymentCaptureFailed` entry is appended to the event log
/// and pushed to the receive buffer to provide a durable audit trail (H19).
///
/// # Collaborators
///
/// - `mgr` — delegates to
///   [`ContextManager::complete_paid_action`](crate::context::manager::ContextManager::complete_paid_action)
///   and
///   [`ContextManager::record_payment_capture_failure`](crate::context::manager::ContextManager::record_payment_capture_failure)
///   (both pub(crate)).
///
/// # Behavior preservation
///
/// Byte-identical to the legacy method form.
pub async fn capture_send_payment(
    supervisor: &Supervisor,
    auth: Option<manager::economy::PaidActionAuthorization>,
    sender_did: &DID,
    context_id: &str,
    deducted_cost: Option<scp_protocol::economy::types::Amount>,
) {
    // ADR-049 commit 12c.9c — `capture_send_payment` returns `()` so
    // an unpopulated attach slot degrades to a no-op. The attach
    // contract guarantees the slot is populated at call time; the
    // early-return is defense-in-depth against a contract violation.
    let Some(mgr) = supervisor.attached_context_manager() else {
        tracing::error!(
            context_id,
            "capture_send_payment: Supervisor is not attached — \
             skipping payment capture (contract violation; see ADR-049 commit 12c.9c)"
        );
        return;
    };
    if let Some(a) = auth
        && let Err(e) = mgr.complete_paid_action(a, sender_did, context_id).await
    {
        // H8: do NOT rollback budget — service was delivered.
        tracing::warn!(
            context_id,
            "payment capture failed after successful send: {e}"
        );
        // H19: append durable audit record to event log + receive buffer.
        mgr.record_payment_capture_failure(
            context_id,
            "send_message",
            sender_did,
            &e.to_string(),
            deducted_cost,
        )
        .await;
    }
}

// ---------------------------------------------------------------------------
// 12. finalize_send (hoisted in commit 12c.1b)
// ---------------------------------------------------------------------------

/// Pushes a `MessageSent` event, appends to the event log, and persists.
///
/// Extracted from the [`send_message`] orchestration so the outer
/// function stays within the clippy `too_many_lines` limit.
///
/// # Collaborators
///
/// - `mgr` — reaches `event_log_ref()` (append + Merkle root),
///   `clock_ref()` (`now_secs` for consequence evaluation),
///   `event_tx_ref()` (external fan-out channel), and the pub(crate)
///   methods `relock_context`, `has_persistence`,
///   `persist_context_snapshot`, and `create_checkpoint_if_due`.
///   `ContextManager::snapshot_context` is called as an associated fn
///   (the legacy `Self::snapshot_context(ctx)` site).
///
/// # Behavior preservation
///
/// Byte-identical to the legacy method form. Pipeline-wiring assertion
/// `extract_fn_body(MANAGER_SRC, "finalize_send")` must contain
/// `create_checkpoint_if_due` — the call site here preserves that
/// literal text (`mgr.create_checkpoint_if_due(...)`).
#[allow(clippy::too_many_arguments)] // Retains legacy method signature plus explicit `mgr` param per ADR-049 §12c.1b.
#[allow(clippy::significant_drop_tightening)] // Legacy body held `relock_context` guard across await points deliberately — narrowing changes lock-ordering semantics.
pub async fn finalize_send(
    supervisor: &Supervisor,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    sender_did: &DID,
    sequence: u64,
    payload: &[u8],
    signing_key: Option<&ed25519_dalek::SigningKey>,
    ctx_gen: &manager::ContextGeneration,
) -> Result<(), ContextError> {
    let mgr = supervisor
        .attached_context_manager()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    // M12: Append event log BEFORE consequence evaluation so that
    // event_log_entries_for_consequences sees the current event.
    // Periodic consequence timers only read from the event log (not
    // the receive buffer), so the event must be persisted first.
    supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
        .append_context_event(context_id_bytes, "MessageSent", sender_did.as_ref())?;
    // Phase 3 reacquire with generation check — detects if the context
    // was removed and recreated between Phase 1 and Phase 3.
    {
        let now = supervisor
            .clock_ref()
            .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
            .now_secs();
        if let Ok(mut guard) = mgr.relock_context(ctx_gen).await {
            let ctx = &mut *guard;
            if manager::require_active(&ctx.handle).is_err() {
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
            ctx.emit_event(sent_event, context_id, supervisor.event_tx_ref());

            // Velocity already recorded in send_message Phase 1 (M4: before
            // economy enforcement). No duplicate record_message here.

            // Consequence enforcement (#1531) — evaluate rules, then dispatch.
            // evaluate_consequence_rules is called here so the pipeline wiring
            // gate can detect it in messaging.rs (not hidden inside dispatch_consequences).
            //
            // The same event snapshot is reused for both consequence evaluation
            // and participation record computation (finding #46 dedup).
            let send_events = manager::governance::event_log_entries_for_consequences(
                ctx,
                context_id,
                now,
                &**supervisor
                    .event_log_ref()
                    .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
            );
            let consequence_rules: Vec<ConsequenceRule> = ctx.governance.consequence_rules.clone();
            // evaluate_consequence_rules is called as an expression_statement
            // (not a let_declaration) so the NO-DISCARD-MSG gate passes.
            let send_triggered = evaluate_consequence_rules(
                &consequence_rules,
                &send_events,
                sender_did.as_ref(),
                now,
            );
            manager::governance::enforce_triggered_consequences(
                ctx,
                &manager::governance::EnforceConsequencesCtx {
                    context_id,
                    member_did: sender_did,
                    now,
                    triggered: &send_triggered,
                    rules: &consequence_rules,
                    clock: &**supervisor
                        .clock_ref()
                        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
                    event_log: &**supervisor
                        .event_log_ref()
                        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
                    event_tx: supervisor.event_tx_ref(),
                },
            );

            // Participation record update (#1530) — refresh cache after send.
            // Reuses `send_events` from above to avoid a second
            // event_log_entries_for_consequences call.
            let send_merkle = mgr
                .event_log_ref()
                .event_log_merkle_root(context_id_bytes)
                .unwrap_or([0u8; 32]);
            if !send_events.is_empty()
                && let Ok(record) = scp_protocol::trust::participation::compute_participation_record(
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
                mgr.create_checkpoint_if_due(context_id, ctx, sender_did, sk);
            }
        } else {
            tracing::warn!(
                context_id,
                "finalize_send: generation mismatch or context removed — \
                 consequence evaluation skipped"
            );
        }
    }
    if mgr.has_persistence()
        && let Ok(guard) = mgr.relock_context(ctx_gen).await
    {
        let ctx = &*guard;
        let snapshot = ContextManager::snapshot_context(ctx);
        mgr.persist_context_snapshot(context_id, snapshot);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 13. decrypt_and_dispatch (hoisted in commit 12c.1b)
// ---------------------------------------------------------------------------

/// Decrypts an incoming envelope and dispatches management/control
/// messages.
///
/// Returns `Some(OpenedEnvelope)` for application messages that need
/// further processing, or `None` for control/management messages that
/// are handled internally.
///
/// # Collaborators
///
/// - `mgr` — reaches `crypto_ref()` for the open + sender-key processing
///   calls. No other state access.
///
/// # Behavior preservation
///
/// Byte-identical to the legacy method form. Pipeline-wiring assertion
/// `fn_body_contains(MANAGER_SRC, "decrypt_and_dispatch", ".open(")`
/// is satisfied because `supervisor.crypto_ref().ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?.open(...)` preserves the
/// literal `.open(` text.
pub fn decrypt_and_dispatch(
    supervisor: &Supervisor,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    encrypted_blob: &[u8],
) -> Result<Option<scp_protocol::context::builder::OpenedEnvelope>, ContextError> {
    // `mgr` is unused in this helper post-12c.9c (crypto is reached via
    // `supervisor.crypto_ref()`); the derivation is omitted.
    let decrypt_start = std::time::Instant::now();
    let open_result = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
        .open(context_id_bytes, encrypted_blob)?;
    crate::metrics::record_decrypt_duration(decrypt_start.elapsed());

    match open_result {
        scp_protocol::context::builder::OpenResult::Application(env) => Ok(Some(*env)),
        scp_protocol::context::builder::OpenResult::Control => Ok(None),
        scp_protocol::context::builder::OpenResult::Management {
            sender_did,
            payload,
        } => {
            tracing::debug!(sender_did = %sender_did, context_id = %context_id, "received MLS-wrapped management message");
            supervisor
                .crypto_ref()
                .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
                .process_incoming_sender_key(context_id_bytes, &sender_did, &payload)?;
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// 14. validate_and_drain_timeouts (hoisted in commit 12c.1b)
// ---------------------------------------------------------------------------

/// Validates timestamp and sequence, then drains timed-out gaps.
///
/// Returns the `SequenceCheck` result for the caller to decide whether
/// to deliver immediately or buffer.
///
/// # Collaborators
///
/// - `mgr` — reaches `get_context_arc_pub()` (contextsmap lookup),
///   `event_tx_ref()` (external fan-out), `clock_ref()` (no-op here
///   but fed to `run_buffered_post_delivery`), and `event_log_ref()`
///   (also fed to `run_buffered_post_delivery`).
///
/// # Behavior preservation
///
/// Byte-identical to the legacy method form. Pipeline-wiring assertion
/// `fn_body_contains(MANAGER_SRC, "validate_and_drain_timeouts",
/// "tv.validate")` is preserved by the literal `tv.validate(...)` call
/// below.
#[allow(clippy::significant_drop_tightening)] // Legacy body held per-context guard across await points deliberately — narrowing changes lock-ordering semantics.
pub async fn validate_and_drain_timeouts(
    supervisor: &Supervisor,
    context_id: &str,
    inner: &scp_protocol::envelope::inner::InnerEnvelope,
    now_ms: u64,
) -> Result<SequenceCheck, ContextError> {
    let mgr = supervisor
        .attached_context_manager()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let ctx_arc = mgr
        .get_context_arc_pub(context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let mut guard = ctx_arc.lock().await;
    let ctx = &mut *guard;

    // Timestamp validation first — reject timestamps out of bounds.
    let tv = scp_protocol::envelope::validation::TimestampValidator::default();
    tv.validate(inner, now_ms)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    // Sequence check: replay detection + gap detection (§9.8.5).
    let check = ctx
        .sequence_tracker
        .validate(inner)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    // Also drain any timed-out gaps on each delivery call.
    let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);
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
        ctx.emit_event(gap_event, context_id, supervisor.event_tx_ref());
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
                supervisor.event_tx_ref(),
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
                    &**supervisor
                        .clock_ref()
                        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
                    &**supervisor
                        .event_log_ref()
                        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
                    supervisor.event_tx_ref(),
                );
            }
        }
    }

    Ok(check)
}

// ---------------------------------------------------------------------------
// 15. buffer_ahead_message (hoisted in commit 12c.1b)
// ---------------------------------------------------------------------------

/// Buffers an out-of-order message that arrived ahead of expected
/// sequence.
///
/// If the buffer overflows, force-closes the oldest gap and delivers
/// all its messages.
///
/// # Collaborators
///
/// - `mgr` — reaches `get_context_arc_pub()`, `event_tx_ref()`,
///   `clock_ref()`, `event_log_ref()` for the overflow force-delivery
///   path.
///
/// # Behavior preservation
///
/// Byte-identical to the legacy method form.
#[allow(clippy::significant_drop_tightening)] // Legacy body held per-context guard across await points deliberately — narrowing changes lock-ordering semantics.
pub async fn buffer_ahead_message(
    supervisor: &Supervisor,
    context_id: &str,
    inner: &scp_protocol::envelope::inner::InnerEnvelope,
    sender_did: &str,
    plaintext: &[u8],
    now_ms: u64,
) -> Result<(), ContextError> {
    let mgr = supervisor
        .attached_context_manager()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let buffered_msg = scp_protocol::envelope::validation::BufferedMessage {
        inner: inner.clone(),
        sender_did: sender_did.to_owned(),
        plaintext: plaintext.to_vec(),
        received_at: now_ms,
    };

    let ctx_arc = mgr
        .get_context_arc_pub(context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let mut guard = ctx_arc.lock().await;
    let ctx = &mut *guard;

    if let Some((mut gap_info, messages)) = ctx.reorder_buffer.buffer(buffered_msg) {
        let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);
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
        ctx.emit_event(gap_event, context_id, supervisor.event_tx_ref());

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
                supervisor.event_tx_ref(),
            ) {
                // Bug fix (#1534): overflow-forced delivery now runs
                // consequence evaluation, matching the direct path.
                run_buffered_post_delivery(
                    ctx,
                    context_id,
                    &context_id_bytes,
                    &msg.sender_did,
                    event_name,
                    &**supervisor
                        .clock_ref()
                        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
                    &**supervisor
                        .event_log_ref()
                        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
                    supervisor.event_tx_ref(),
                );
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 16. deliver_message_and_drain_buffered (hoisted in commit 12c.1b)
// ---------------------------------------------------------------------------

/// Delivers a message that is in sequence order, advances the tracker,
/// checks membership and capability, pushes the event, and then drains
/// any consecutive buffered messages that are now unblocked.
///
/// `skip_velocity` is `true` when the sender is a locally-controlled DID
/// (i.e. the same node that sent the message). In that case velocity is
/// already recorded on the send path and must not be counted again here,
/// otherwise a single message would be double-counted on single-node
/// setups.
///
/// # Collaborators
///
/// - `mgr` — reaches `get_context_arc_pub()`, `event_tx_ref()`,
///   `event_log_ref()`, `clock_ref()`.
///
/// # Behavior preservation
///
/// Byte-identical to the legacy method form.
#[allow(clippy::too_many_lines)] // Matches legacy method shape exactly; splitting further would fragment the shared lock scope.
#[allow(clippy::significant_drop_tightening)] // Legacy body held per-context guard across await points deliberately — narrowing changes lock-ordering semantics.
pub async fn deliver_message_and_drain_buffered(
    supervisor: &Supervisor,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    sender_did: &str,
    inner: &scp_protocol::envelope::inner::InnerEnvelope,
    plaintext: &[u8],
    skip_velocity: bool,
) -> Result<bool, ContextError> {
    let mgr = supervisor
        .attached_context_manager()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let sender_did_obj = DID(sender_did.to_owned());

    let ctx_arc = mgr
        .get_context_arc_pub(context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let mut guard = ctx_arc.lock().await;
    let ctx = &mut *guard;
    manager::require_active(&ctx.handle)?;

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
    if let Ok(announcement) = rmp_serde::from_slice::<PseudonymAnnouncement>(plaintext)
        && announcement.tag == PSEUDONYM_ANNOUNCEMENT_TAG
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
        ctx.emit_event(announce_event, context_id, supervisor.event_tx_ref());
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
                supervisor.event_tx_ref(),
            ) {
                // Bug fix (#1534): drain_consecutive within announcement
                // path now runs consequence evaluation per message.
                run_buffered_post_delivery(
                    ctx,
                    context_id,
                    context_id_bytes,
                    &msg.sender_did,
                    event_name,
                    &**supervisor
                        .clock_ref()
                        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
                    &**supervisor
                        .event_log_ref()
                        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
                    supervisor.event_tx_ref(),
                );
            }
        }

        // Velocity, consequence, event log — same as normal messages.
        // Bug fix (#1534): consequence evaluation was previously missing from
        // the announcement path, allowing a malicious member to send
        // announcements at high velocity without triggering rate-limiting
        // consequences. Now both paths share identical post-delivery logic.
        let now = supervisor
            .clock_ref()
            .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
            .now_secs();
        if !skip_velocity {
            ctx.governance
                .velocity_tracker
                .record_message(&DID(sender_did.to_owned()), now);
        }
        if let Err(e) = supervisor
            .event_log_ref()
            .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
            .append_context_event(context_id_bytes, "PseudonymAnnounced", sender_did)
        {
            tracing::warn!(
                context_id,
                sender_did,
                "failed to append PseudonymAnnounced to event log: {e}"
            );
        }
        let consequence_rules: Vec<ConsequenceRule> = ctx.governance.consequence_rules.clone();
        if !consequence_rules.is_empty() {
            let recv_events = manager::governance::event_log_entries_for_consequences(
                ctx,
                context_id,
                now,
                &**supervisor
                    .event_log_ref()
                    .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
            );
            let recv_triggered =
                evaluate_consequence_rules(&consequence_rules, &recv_events, sender_did, now);
            let recv_member_did = DID(sender_did.to_owned());
            manager::governance::enforce_triggered_consequences(
                ctx,
                &manager::governance::EnforceConsequencesCtx {
                    context_id,
                    member_did: &recv_member_did,
                    now,
                    triggered: &recv_triggered,
                    rules: &consequence_rules,
                    clock: &**supervisor
                        .clock_ref()
                        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
                    event_log: &**supervisor
                        .event_log_ref()
                        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
                    event_tx: supervisor.event_tx_ref(),
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
    ctx.emit_event(recv_event, context_id, supervisor.event_tx_ref());

    // Drain consecutive buffered messages that are now unblocked (§9.8.5).
    let next_expected = inner.sequence.saturating_add(1);
    let consecutive = ctx
        .reorder_buffer
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
            supervisor.event_tx_ref(),
        ) {
            // Bug fix (#1534): drain_consecutive within normal message
            // path now runs consequence evaluation per message.
            run_buffered_post_delivery(
                ctx,
                context_id,
                context_id_bytes,
                &msg.sender_did,
                event_name,
                &**supervisor
                    .clock_ref()
                    .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
                &**supervisor
                    .event_log_ref()
                    .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
                supervisor.event_tx_ref(),
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
    if let Err(e) = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
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
    let now = supervisor
        .clock_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
        .now_secs();
    if !skip_velocity {
        ctx.governance
            .velocity_tracker
            .record_message(&DID(sender_did.to_owned()), now);
    }
    let consequence_rules: Vec<ConsequenceRule> = ctx.governance.consequence_rules.clone();
    if !consequence_rules.is_empty() {
        let recv_events = manager::governance::event_log_entries_for_consequences(
            ctx,
            context_id,
            now,
            &**supervisor
                .event_log_ref()
                .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
        );
        let recv_triggered =
            evaluate_consequence_rules(&consequence_rules, &recv_events, sender_did, now);
        let recv_member_did = DID(sender_did.to_owned());
        manager::governance::enforce_triggered_consequences(
            ctx,
            &manager::governance::EnforceConsequencesCtx {
                context_id,
                member_did: &recv_member_did,
                now,
                triggered: &recv_triggered,
                rules: &consequence_rules,
                clock: &**supervisor
                    .clock_ref()
                    .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
                event_log: &**supervisor
                    .event_log_ref()
                    .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
                event_tx: supervisor.event_tx_ref(),
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
