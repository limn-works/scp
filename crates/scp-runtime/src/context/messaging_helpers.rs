//! Messaging helpers — actor-shape signatures
//! (ADR-049 Phase 2A.7, `messaging` domain migration).
//!
//! # Purpose
//!
//! This module hosts messaging-domain helpers that operate on actor-owned
//! [`PerContextState`](crate::context::actor::state::PerContextState) and
//! capability-reduced [`ActorDeps`](crate::context::actor::deps::ActorDeps).
//! The legacy `&Supervisor` lock-and-call bodies live in
//! [`crate::context::messaging_helpers_legacy`] until Phase 2A
//! finalization removes the shim fallback.
//!
//! # Pipeline shape
//!
//! Actor-owned state collapses the legacy send path's three-phase
//! lock dance (under-lock → off-lock → relock) into a single linear
//! flow: the actor's mailbox already serializes per-context commands,
//! so encryption and transport fan-out happen with `state` still
//! borrowed. No relock / generation-token confused-deputy dance is
//! needed because each actor is its own generation.
//!
//! # Helpers
//!
//! 1. [`build_encrypted_envelope`] — pure: access-key wrap, inner
//!    envelope sign+pad, sender-key + MLS + outer-envelope seal.
//! 2. [`enforce_send_economy`] — unified economy enforcement against
//!    actor-owned governance state.
//! 3. [`build_broadcast_envelope`] — broadcast-mode publish (pure).
//! 4. [`verify_and_unwrap`] — pure: inner-signature verify, padding
//!    strip, content integrity, access-key unwrap (or Recovery gate).
//! 5. [`deliver_plaintext_or_announcement`] — buffered/drained
//!    delivery (announcement vs regular).
//! 6. [`run_buffered_post_delivery`] — post-delivery governance
//!    (velocity, event-log, consequence eval, checkpoint) for
//!    buffered messages.
//! 7. [`send_message`] — top-level send path (actor-shape).
//! 8. [`deliver_incoming`] — top-level receive path (actor-shape).
//! 9. [`encrypt_and_send`] — Phase 2 encrypt + transport fan-out.
//! 10. [`authorize_send_payment`] — Phase 1.5 escrow auth.
//! 11. [`capture_send_payment`] — Phase 3 escrow capture.
//! 12. [`finalize_send`] — event-log append + consequence eval +
//!     checkpoint + persistence.
//! 13. [`decrypt_and_dispatch`] — open + management-message handling.
//! 14. [`validate_and_drain_timeouts`] — timestamp + sequence
//!     validate + reorder-buffer timeout drain.
//! 15. [`buffer_ahead_message`] — buffer out-of-order, force-deliver
//!     on overflow.
//! 16. [`deliver_message_and_drain_buffered`] — in-order delivery +
//!     drain consecutive buffered.
//! 17. [`send_pseudonym_announcement`] — best-effort announcement.

use std::sync::Arc;

use sha2::Digest;
use subtle::ConstantTimeEq;

use scp_identity::DID;
use scp_primitives::Clock;
use scp_protocol::context::ContextError;
use scp_protocol::context::broadcast::BroadcastContext;
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
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::governance_helpers;
use crate::context::state::{
    self, CHECKPOINT_PAYLOAD_TAG, CheckpointMessage, PSEUDONYM_ANNOUNCEMENT_TAG,
    PseudonymAnnouncement, emit_event_into,
};
use crate::crypto::mls::provider::MlsCryptoProvider;

/// Alias for the broadcast channel used to fan out [`ContextEvent`]s to
/// external subscribers (webhook dispatcher, SDK event streams).
pub type ContextEventSender = tokio::sync::broadcast::Sender<(String, ContextEvent)>;

/// Default TTL (in seconds) for sealed message blobs sent through the
/// transport. 300s = 5 minutes — short enough to limit replay surface,
/// long enough to absorb transient relay outages.
///
/// Public so the lifecycle path can re-use the same value when sealing
/// welcome envelopes.
pub const DEFAULT_BLOB_TTL_SECS: u32 = 300;

// ---------------------------------------------------------------------------
// 1. build_encrypted_envelope
// ---------------------------------------------------------------------------

/// Builds the encrypted envelope bytes for the send path.
///
/// Pure helper — no per-context state. Identical to the legacy
/// [`crate::context::messaging_helpers_legacy::build_encrypted_envelope_legacy`]
/// body; carried here so the actor-shape send path does not have to
/// import from the legacy module.
///
/// # Routing
///
/// The outer envelope's cleartext `routing_id` is zeroed (`[0u8; 32]`) for
/// application data: a single sealed blob fans out to N per-member pseudonym
/// transport addresses, so no single per-recipient value belongs in the
/// envelope, and embedding the relay-derivable `context_routing_id` would leak
/// a correlator to the relay (§9.10.4). The receiver ignores this field for
/// app-data, routing on the transport key instead.
#[allow(clippy::too_many_arguments)]
pub fn build_encrypted_envelope(
    clock: &Arc<dyn Clock>,
    crypto: &Arc<MlsCryptoProvider>,
    context_id: &str,
    sender_did: &DID,
    payload: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
    recipients_data: &std::collections::HashMap<String, AccessKey>,
    sequence: u64,
    source_provenance: Option<&SourceContextInfo>,
    message_type: MessageType,
) -> Result<Vec<u8>, ContextError> {
    let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);
    let provenance = source_provenance.map(|source_info| {
        let target_context: scp_protocol::provenance::ContextId = context_id.to_owned();
        let dp = scp_protocol::provenance::attach::attach_provenance(
            source_info,
            &target_context,
            None,
            None,
            None,
        );
        scp_protocol::envelope::inner::Provenance {
            source: dp.source_context,
            upstream_hash: None,
        }
    });

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

    let timestamp = clock.now_millis();
    let params = InnerEnvelopeParams {
        version: scp_protocol::envelope::SCP_PROTOCOL_VERSION,
        context_id,
        sender_did: sender_did.as_ref(),
        epoch: 0,
        generation: 0,
        sequence,
        timestamp,
        message_type,
        payload: &wrapped_bytes,
        provenance,
        signing_key_id: SigningKeyId::Active,
    };

    let inner = crate::envelope::inner::sign::create_inner_envelope_raw(&params, signing_key)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    // §9.10.4 privacy: the cleartext outer-envelope `routing_id` is zeroed for
    // application data. One sealed blob is fanned out to N per-member pseudonym
    // transport addresses (seal-once-send-to-all), so there is no single
    // per-recipient value to embed here. Embedding the relay-derivable
    // `context_routing_id(context_id)` would let a curious relay read it off
    // every pseudonym-addressed app-data blob and re-correlate all senders,
    // defeating the pseudonym scheme. The all-zero value is a RESERVED/forbidden
    // pseudonym (§9.10.4), so it cannot collide with a real routing ID, and the
    // receiver never reads this field for app-data (it routes on the transport
    // key and MLS-decrypts `encrypted_blob`), so receive is unaffected.
    // `create_outer_envelope` enforces `routing_id.len() == 32`, which a
    // 32-byte zero sentinel satisfies.
    let routing_id = [0u8; 32];
    crypto.seal(
        &context_id_bytes,
        &inner,
        &routing_id,
        DEFAULT_BLOB_TTL_SECS,
    )
}

// ---------------------------------------------------------------------------
// 2. enforce_send_economy
// ---------------------------------------------------------------------------

/// Enforces economic policy for message sends (#1537, #1593).
///
/// Actor-shape variant: takes `&mut PerContextState` directly, no
/// supervisor lock dance.
pub fn enforce_send_economy(
    state: &mut PerContextState,
    sender_did: &DID,
    now: u64,
    spending_ucan: Option<&UcanToken>,
    context_id: &str,
    clock: &dyn Clock,
    key_resolver: &KeyResolver,
) -> Result<Option<scp_protocol::economy::types::Amount>, ContextError> {
    let pricing_default =
        scp_protocol::economy::antispam::ContextMessagePricingConfig::spec_default();
    let member_count = state.membership.count();
    let governance = &mut state.governance;
    let pricing = governance
        .message_pricing
        .as_ref()
        .unwrap_or(&pricing_default);
    crate::context::economy_logic::enforce_economy(
        crate::context::economy_logic::EnforceEconomyRequest {
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
        },
    )
}

// ---------------------------------------------------------------------------
// 3. build_broadcast_envelope
// ---------------------------------------------------------------------------

/// Builds a broadcast envelope for the send path. Pure helper.
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

/// Verifies signature and unwraps access keys. Pure helper.
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

    let stripped = scp_protocol::envelope::padding::strip_padding(&inner.payload)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    let computed_hash: [u8; 32] = sha2::Sha256::digest(&stripped).into();
    if !bool::from(computed_hash[..].ct_eq(&inner.payload_hash[..])) {
        return Err(ContextError::CryptoFailed(
            "content integrity check failed".into(),
        ));
    }

    if inner.message_type == MessageType::Recovery {
        if !sender_is_admin {
            return Err(ContextError::PermissionDenied(
                "only admins can send Recovery-type messages".into(),
            ));
        }
        return Ok(stripped);
    }

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
/// pseudonym announcement first.
///
/// The return is an optional [`scp_event_log::EventType`] — the event to
/// durably append for the delivered message — but ALL received traffic is
/// buffer-only, so this currently always returns `None`: ordinary application
/// messages, pseudonym announcements (a §9.10.4 routing-bootstrap signal handled
/// via the in-memory peer registry + `ContextEvent::PseudonymAnnounced` buffer
/// emit), and silently-dropped rejections alike. A receiver-minted Merkle leaf
/// is not sender-authenticated and would diverge honest receivers' roots
/// (§9.9.3). The `Some` channel is retained so a future sender-authenticated
/// received event can opt into a durable append without re-plumbing the
/// buffered-drain call sites.
pub fn deliver_plaintext_or_announcement(
    state: &mut PerContextState,
    sender_did: &str,
    plaintext: &[u8],
    context_id: &str,
    event_tx: Option<&ContextEventSender>,
) -> Option<scp_event_log::EventType> {
    // §9.10.4: run the shared announcement-ingest validator. The buffered path
    // maps a rejection to `None` (silent drop) — the message has already been
    // buffered/reordered, so there is no caller to return a typed error to.
    match ingest_pseudonym_announcement(state, sender_did, plaintext, context_id, event_tx) {
        AnnouncementOutcome::Recorded => {
            tracing::debug!(
                context_id,
                sender_did,
                "processed buffered pseudonym announcement"
            );
            // A received pseudonym announcement is a §9.10.4 routing-bootstrap
            // signal, NOT a durable Merkle event. `ingest_pseudonym_announcement`
            // already inserted the peer's routing ID into the in-memory registry
            // and emitted `ContextEvent::PseudonymAnnounced` to the receive
            // buffer (the announcement's entire function). Returning `None`
            // suppresses any durable append, exactly as for received application
            // messages (`NotAnnouncement` below): a per-receiver, per-arrival-order
            // append cannot converge across honest members (late joiners miss
            // earlier announcements; WASM never appends on receive), which would
            // false-positive §9.9.3 equivocation detection.
            None
        }
        AnnouncementOutcome::Rejected(_reason) => None,
        AnnouncementOutcome::NotAnnouncement => {
            // Received application messages are pushed to the in-memory
            // receive buffer for SDK observation, but NOT appended to the
            // durable Merkle event log: a receiver-minted MessageReceived leaf
            // is not authenticated by the sender, so logging it would let two
            // honest receivers compute divergent Merkle roots for the same
            // context and trip §9.9.3 equivocation detection. Returning `None`
            // suppresses the append while preserving the buffer push.
            let event = ContextEvent::MessageReceived {
                sender_did: DID(sender_did.to_owned()),
                payload: plaintext.to_vec(),
            };
            emit_event_into(&mut state.receive_buffer, event, context_id, event_tx);
            None
        }
    }
}

// ---------------------------------------------------------------------------
// §9.10.4 announcement / routing helpers
// ---------------------------------------------------------------------------

/// Classifies a send-path payload as a `PseudonymAnnouncement` (§9.10.4).
///
/// Announcements are the ONLY payload class permitted to use the shared
/// `context_routing_id` as an addressee — they form the bootstrap channel
/// peers use to learn each other's pseudonyms before regular app data can fan
/// out on pseudonym-only paths. Returns `true` only when the payload
/// deserializes as a well-formed `PseudonymAnnouncement` AND carries the magic
/// tag (`PSEUDONYM_ANNOUNCEMENT_TAG`, `\0`-prefixed to avoid collision with
/// UTF-8 user content). False positives from adversarial payloads cannot
/// escalate: the worst outcome is a legitimate app message routed to the
/// shared RID, which is not a confidentiality issue (MLS still gates content)
/// and is detected as a non-announcement on the receive path.
fn is_pseudonym_announcement_payload(payload: &[u8]) -> bool {
    rmp_serde::from_slice::<PseudonymAnnouncement>(payload)
        .is_ok_and(|a| a.tag == PSEUDONYM_ANNOUNCEMENT_TAG)
}

/// Returns `true` if `pseudonym` is a reserved routing ID a member is not
/// permitted to announce as their own (§9.10.4).
///
/// The pseudonym registry maps each member's DID to the routing ID honest
/// senders fan their app-data ciphertext out to. If a member could announce a
/// reserved value for their own DID, they could redirect every honest sender's
/// app-data:
///
/// - `[0u8; 32]` — the zero/degraded sentinel; maps to nothing meaningful.
/// - `context_routing_id(context_id)` — the shared bootstrap RID; announcing
///   it would push app-data ciphertext onto the shared channel, defeating
///   unlinkability.
/// - `broadcast_routing_id(context_id)` — the derivable `SHA-256(context_id)`
///   broadcast RID; same leak vector.
///
/// Honest pseudonyms are the raw 32-byte Ed25519 public key of the member's
/// per-context keypair (stored and routed on verbatim, NOT hashed). They
/// collide with these reserved values only with negligible probability, so
/// rejecting them costs nothing for legitimate members.
fn is_reserved_pseudonym(pseudonym: &[u8; 32], context_id: &str) -> bool {
    *pseudonym == [0u8; 32]
        || *pseudonym == scp_protocol::context::context_routing_id(context_id)
        || *pseudonym == scp_protocol::context::broadcast_routing_id(context_id)
}

/// Returns `true` if `pseudonym` is already registered under a DID OTHER than
/// `announcer_did` (§9.10.4 defense-in-depth).
///
/// The announcement path already enforces `announcement.member_did ==
/// sender_did`, so a member can only announce a routing ID for their own DID.
/// This guards the remaining vector: a member claiming a routing ID an
/// existing peer already legitimately uses, which would let two DIDs resolve
/// to one routing ID (a relay would then receive both members' fan-out at one
/// address, and honest senders addressing the colliding DID could misroute).
/// A member re-announcing the SAME value for their OWN DID is legitimate (key
/// rotation re-broadcast) and is NOT a collision.
fn pseudonym_collides_with_other_did(
    registry: &std::collections::HashMap<DID, [u8; 32]>,
    announcer_did: &DID,
    pseudonym: &[u8; 32],
) -> bool {
    registry.iter().any(|(other_did, other_pseudonym)| {
        other_pseudonym == pseudonym && other_did != announcer_did
    })
}

/// Outcome of running the shared §9.10.4 pseudonym-announcement ingest
/// validator over a single inbound plaintext.
///
/// Each call site maps this to its OWN return convention: the buffered path
/// drops a `Rejected` to `None`, the direct path maps it to
/// `Err(PermissionDenied)`. `NotAnnouncement` means the plaintext is ordinary
/// application data (not a tagged announcement) and should be delivered as a
/// normal message.
pub enum AnnouncementOutcome {
    /// The plaintext was a well-formed announcement that passed every check;
    /// the peer registry was updated and a `PseudonymAnnounced` event emitted.
    Recorded,
    /// The plaintext is not a tagged `PseudonymAnnouncement` — deliver it as a
    /// normal application message.
    NotAnnouncement,
    /// The plaintext was a tagged announcement that FAILED a security check.
    /// The metric/warn have already fired inside the validator; the carried
    /// reason is a stable `&'static str` for the caller's error/diagnostic.
    Rejected(&'static str),
}

/// Shared §9.10.4 pseudonym-announcement ingest validator — the single
/// security boundary for both ingest sites (`deliver_plaintext_or_announcement`
/// for buffered/reordered messages, `deliver_message_and_drain_buffered` for
/// in-order messages).
///
/// Runs the four-step validation core ONCE so the two sites cannot drift:
/// 1. tag-decode (`NotAnnouncement` if the plaintext is not a tagged
///    announcement),
/// 2. `member_did == sender_did` (forged-announcement guard),
/// 3. reserved-value rejection (`is_reserved_pseudonym`),
/// 4. broadcast-context reject + cross-DID collision
///    (`pseudonym_collides_with_other_did`), then registry insert + event emit.
///
/// On any rejection the rejection metric is recorded and a warning is logged
/// HERE, so neither call site has to. The validator STOPS at "record + emit":
/// the direct site's follow-up (sequence-tracker advance, reorder-buffer drain,
/// velocity, event-log append, consequence evaluation) stays at that call site
/// and is NOT part of this shared core.
fn ingest_pseudonym_announcement(
    state: &mut PerContextState,
    sender_did: &str,
    plaintext: &[u8],
    context_id: &str,
    event_tx: Option<&ContextEventSender>,
) -> AnnouncementOutcome {
    // Step 1: tag-decode. A non-announcement (or untagged payload) is ordinary
    // application data.
    let Ok(announcement) = rmp_serde::from_slice::<PseudonymAnnouncement>(plaintext) else {
        return AnnouncementOutcome::NotAnnouncement;
    };
    if announcement.tag != PSEUDONYM_ANNOUNCEMENT_TAG {
        return AnnouncementOutcome::NotAnnouncement;
    }

    // Step 2: the announced DID must match the authenticated sender. A member
    // can only announce a routing ID for their OWN DID.
    if announcement.member_did != sender_did {
        crate::metrics::record_pseudonym_announcement_rejected();
        tracing::warn!(
            context_id,
            sender_did,
            claimed_did = %announcement.member_did,
            "pseudonym announcement sender mismatch — rejecting forged announcement"
        );
        return AnnouncementOutcome::Rejected(
            "pseudonym announcement member_did does not match sender",
        );
    }

    let announced_did = DID(announcement.member_did.clone());

    // Step 3: reject reserved pseudonym VALUES before touching the registry.
    // Announcing the zero sentinel, the shared bootstrap RID, or the broadcast
    // RID for one's own DID would redirect every honest sender's app-data
    // fan-out, defeating unlinkability or leaking ciphertext onto the shared
    // channel.
    if is_reserved_pseudonym(&announcement.pseudonym, context_id) {
        crate::metrics::record_pseudonym_announcement_rejected();
        tracing::warn!(
            context_id,
            sender_did,
            "pseudonym announcement uses a reserved routing ID — rejecting"
        );
        return AnnouncementOutcome::Rejected("pseudonym announcement uses a reserved routing ID");
    }

    // Step 4: registry updates are meaningful only for encrypted contexts. A
    // broadcast context carries no peer registry — reject as a spec-level
    // violation. Otherwise reject a routing ID already claimed by a DIFFERENT
    // member (same-DID re-announce for key rotation stays allowed), then insert.
    let Some(pseudonym_registry) = state.routing.peer_registry_mut() else {
        crate::metrics::record_pseudonym_announcement_rejected();
        tracing::warn!(
            context_id,
            sender_did,
            "pseudonym announcement received on broadcast context — rejecting"
        );
        return AnnouncementOutcome::Rejected(
            "pseudonym announcement received on broadcast context",
        );
    };
    if pseudonym_collides_with_other_did(
        pseudonym_registry,
        &announced_did,
        &announcement.pseudonym,
    ) {
        crate::metrics::record_pseudonym_announcement_rejected();
        tracing::warn!(
            context_id,
            sender_did,
            "pseudonym announcement collides with another member's routing ID — rejecting"
        );
        return AnnouncementOutcome::Rejected(
            "pseudonym announcement collides with another member's routing ID",
        );
    }
    pseudonym_registry.insert(announced_did.clone(), announcement.pseudonym);

    // Record + emit. The validator stops here; per-site follow-up runs at the
    // call site.
    let event = ContextEvent::PseudonymAnnounced {
        member_did: announced_did,
        pseudonym: announcement.pseudonym,
    };
    emit_event_into(&mut state.receive_buffer, event, context_id, event_tx);
    AnnouncementOutcome::Recorded
}

// ---------------------------------------------------------------------------
// 6. run_buffered_post_delivery
// ---------------------------------------------------------------------------

/// Runs post-delivery governance logic for a single buffered/drained
/// message.
///
/// Governance — velocity tracking, consequence evaluation/enforcement, and the
/// `checkpoint_events_since` increment — runs UNCONDITIONALLY for every
/// delivered buffered message, mirroring the in-order delivery path
/// (`deliver_message_and_drain_buffered`). Two regressions this function is the
/// fix for: (1) buffered messages historically skipped governance entirely; (2)
/// the durable Merkle append is now decoupled — `event_name` is `Some` only for
/// a sender-authenticated received event. No current received-traffic class
/// qualifies: ordinary application messages (`MessageReceived`) and pseudonym
/// announcements (`PseudonymAnnounced`) are both receive-buffer/`ContextEvent`
/// signals, not durable events, so `deliver_plaintext_or_announcement` returns
/// `None` for all received traffic (§9.9.3: a receiver-minted leaf is not
/// sender-authenticated, so appending it — per receiver, in per-receiver arrival
/// order — would let honest receivers compute divergent roots and false-positive
/// equivocation detection). Such messages MUST still record velocity, run
/// consequence eval, and increment the checkpoint counter, only skipping the
/// append. The `Some` branch remains so a future sender-authenticated received
/// event can opt into a durable append without re-plumbing this helper.
#[allow(clippy::too_many_arguments)]
pub fn run_buffered_post_delivery(
    state: &mut PerContextState,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    sender_did: &str,
    event_name: Option<scp_event_log::EventType>,
    clock: &dyn Clock,
    event_log: &dyn crate::context::builder::ContextEventLogProvider,
    event_tx: Option<&ContextEventSender>,
) {
    let now = clock.now_secs();

    // Velocity tracking — always record for buffered messages.
    state
        .governance
        .velocity_tracker
        .record_message(&DID(sender_did.to_owned()), now);

    // Durable Merkle append ONLY for sender-authenticated events. Application
    // messages (`None`) skip the append but still run governance below.
    if let Some(event_name) = event_name
        && let Err(e) = event_log.append_context_event(context_id_bytes, event_name, sender_did)
    {
        tracing::warn!(
            context_id,
            sender_did,
            event_name = ?event_name,
            "failed to append buffered event to event log: {e}"
        );
    }

    let consequence_rules: Vec<ConsequenceRule> = state.governance.consequence_rules.clone();
    if !consequence_rules.is_empty() {
        let events = crate::context::governance_logic::event_log_entries_for_consequences(
            &state.receive_buffer,
            context_id,
            now,
            event_log,
        );
        let triggered = evaluate_consequence_rules(&consequence_rules, &events, sender_did, now);
        let member_did = DID(sender_did.to_owned());
        let mut split = crate::context::governance_logic::ConsequenceStateSplit {
            governance: &mut state.governance,
            role_state: &mut state.role_state,
            membership: &state.membership,
            receive_buffer: &mut state.receive_buffer,
            checkpoint_events_since: &mut state.checkpoint_events_since,
        };
        crate::context::governance_logic::enforce_triggered_consequences(
            &mut split,
            &crate::context::governance_logic::EnforceConsequencesCtx {
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

    state.checkpoint_events_since += 1;
}

// ---------------------------------------------------------------------------
// 7. send_message (top-level, actor-shape)
// ---------------------------------------------------------------------------

/// Sends a message within a context (actor-shape).
///
/// Actor-owned state collapses the legacy three-phase lock dance into a
/// single linear pipeline. The actor's mailbox already serializes
/// per-context commands, so encryption + transport happen with `state`
/// borrowed throughout.
///
/// 1. Capability + commit-fault gate, hard-rate-limit consume, velocity
///    record, economy enforcement, broadcast-envelope build (broadcast)
///    OR sequence assignment + routing-ID list (encrypted) — produces
///    an [`EconomyTicket`](crate::context::economy_logic::EconomyTicket).
/// 2. Payment authorization (escrow hold).
/// 3. Encrypt + transport fan-out.
/// 4. On failure: void escrow, drain ticket, rollback sequence.
/// 5. On success: commit ticket, capture payment, [`finalize_send`].
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
pub async fn send_message(
    state: &mut PerContextState,
    deps: &ActorDeps,
    handle: &ContextHandle,
    sender_did: &DID,
    payload: &[u8],
    signing_key: Option<&ed25519_dalek::SigningKey>,
    source_provenance: Option<&SourceContextInfo>,
    spending_ucan: Option<&UcanToken>,
) -> Result<(), ContextError> {
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = scp_protocol::context::context_id_bytes(&context_id);

    state::require_active(&state.handle)?;
    // Fail-close on commit fault.
    governance_helpers::check_commit_fault_marker(state.commit_fault.as_ref())?;
    // H7: capability check BEFORE budget deduction.
    if state.broadcast_context.is_none()
        && !state
            .role_state
            .member_has_capability(sender_did.as_ref(), &Capability::MessagesWrite)
    {
        let is_suspended = state
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
    // Hard rate limit consume — defense-in-depth.
    let now_secs = deps.clock.now_secs();
    if !state
        .governance
        .hard_rate_limit
        .try_consume(sender_did, now_secs)
    {
        return Err(ContextError::RateLimited {
            resource: "send".to_owned(),
            message: "hard rate limit exceeded for sender".to_owned(),
        });
    }
    // M4: record velocity BEFORE economy enforcement.
    let velocity_token = state
        .governance
        .velocity_tracker
        .record_message(sender_did, now_secs);

    let deducted_cost = match enforce_send_economy(
        state,
        sender_did,
        now_secs,
        spending_ucan,
        &context_id,
        &*deps.clock,
        &deps.key_resolver,
    ) {
        Ok(cost) => cost,
        Err(e) => {
            // Roll back velocity + hard-rate-limit. No EconomyTicket
            // exists yet; rollback inline against actor-owned state.
            state
                .governance
                .velocity_tracker
                .rollback(sender_did, velocity_token);
            state.governance.hard_rate_limit.refund(sender_did);
            return Err(e);
        }
    };
    // F4: wrap Phase 1 economy state in an EconomyTicket.
    let ticket = crate::context::economy_logic::EconomyTicket {
        actor_did: sender_did.clone(),
        deducted_cost,
        velocity_token,
        needs_hard_rate_limit_refund: true,
        consumed: false,
    };

    let (broadcast_envelope, recipients_data, sequence, is_broadcast, send_routing_ids) =
        if let Some(ref mut bc) = state.broadcast_context {
            let Some(sk) = signing_key else {
                crate::context::economy_logic::rollback_economy_ticket_inline(
                    &mut state.governance,
                    ticket,
                );
                return Err(ContextError::CryptoFailed(
                    "signing key required for broadcast publish".into(),
                ));
            };
            let env = match build_broadcast_envelope(&*deps.clock, bc, sender_did, payload, sk) {
                Ok(env) => env,
                Err(e) => {
                    crate::context::economy_logic::rollback_economy_ticket_inline(
                        &mut state.governance,
                        ticket,
                    );
                    return Err(e);
                }
            };
            // Broadcast: SHA-256(context_id) per spec §5.14.
            let broadcast_rid = scp_protocol::context::broadcast_routing_id(&context_id);
            (
                Some(env),
                std::collections::HashMap::new(),
                0,
                true,
                vec![broadcast_rid],
            )
        } else {
            // Encrypted: assign sequence under actor-owned tracker.
            let Some(seq) = state.membership.next_sequence_number(sender_did) else {
                crate::context::economy_logic::rollback_economy_ticket_inline(
                    &mut state.governance,
                    ticket,
                );
                return Err(ContextError::MemberNotFound(format!(
                    "cannot assign sequence: {sender_did} is not a member"
                )));
            };
            // §9.10.4: encrypted contexts fan out to each member's pseudonym
            // routing ID. App data embeds NO correlating routing value: the
            // outer envelope's cleartext `routing_id` is the all-zero sentinel
            // (set in `build_encrypted_envelope`), and the transport address is
            // the per-member pseudonym. The shared `context_routing_id` — which
            // a relay can derive from the public context ID — appears in neither
            // the envelope field nor the transport address for application data,
            // so a relay cannot read a shared correlator off app-data blobs.
            //
            // KNOWN LIMITATION (§9.10.4): the ONE remaining residual is that
            // fan-out sends the SAME MLS ciphertext to all per-member pseudonym
            // addresses. A relay can still correlate pseudonyms by blob-matching
            // (observing identical encrypted blobs across addresses). This is
            // not full unlinkability. Per-recipient re-encryption would fix it
            // but increases bandwidth by O(N); deferred to relay-blinding, which
            // §9.10.4 already documents.
            //
            // Announcement bootstrap channel: `PseudonymAnnouncement` payloads
            // are the ONLY messages permitted to use the shared routing ID, and
            // they go there EXCLUSIVELY — never unioned with peer pseudonyms.
            // Every member subscribes to the shared RID for MLS management
            // traffic, so a single publish reaches every current subscriber
            // regardless of whether we have learned their pseudonym yet. App
            // data continues to fan out to known peer pseudonyms only.
            //
            // Invariant: this branch is the `else` of
            // `broadcast_context.is_some()`, so routing must be pseudonymous.
            debug_assert!(
                !state.routing.is_broadcast(),
                "send fan-out reached the pseudonymous branch with broadcast routing"
            );
            let is_announcement = is_pseudonym_announcement_payload(payload);
            let member_count = state.membership.count();
            let routing_ids: Vec<[u8; 32]> = if is_announcement {
                // Bootstrap path: address the shared RID ONLY.
                vec![scp_protocol::context::context_routing_id(&context_id)]
            } else {
                let peer_pseudonyms: Vec<[u8; 32]> = state
                    .routing
                    .peer_registry()
                    .map(|reg| reg.values().copied().collect())
                    .unwrap_or_default();
                if member_count > 1 && peer_pseudonyms.is_empty() {
                    // App-data send into an encrypted multi-member context
                    // with an empty pseudonym registry would produce zero
                    // sends and silently drop the payload — masking a
                    // bidirectional bootstrap deadlock. Raise a typed error
                    // so callers can distinguish "peers have not announced
                    // yet; retry later" from a transport failure, and roll
                    // back the economy ticket + sequence reservation.
                    crate::context::economy_logic::rollback_economy_ticket_inline(
                        &mut state.governance,
                        ticket,
                    );
                    state.membership.rollback_sequence_number(sender_did);
                    return Err(ContextError::PseudonymRegistryEmpty {
                        context_id: context_id.clone(),
                        member_count,
                    });
                }
                peer_pseudonyms
            };
            (
                None,
                state.access.access_key_store.get_all(&context_id),
                seq,
                false,
                routing_ids,
            )
        };

    // §9.10.4 lone-member no-op: a single-member encrypted context produces an
    // EMPTY app-data routing-ID set (no peers to address; the `member_count > 1`
    // `PseudonymRegistryEmpty` guard above does not fire for a lone member). With
    // no recipients, `encrypt_and_send` makes no transport call and returns
    // `Ok(())` — so committing the economy ticket and emitting `MessageSent`
    // would charge the sender for a message delivered to nobody. Treat this as a
    // true no-op: roll the economy ticket back (mirroring the empty-registry
    // path) and the sequence reservation, and return without a charge or event.
    //
    // This guard fires ONLY for the genuine 0-recipient encrypted app-data case:
    // broadcast sends always carry the shared `broadcast_routing_id`, and
    // `PseudonymAnnouncement` payloads always carry the shared
    // `context_routing_id`, so both are non-empty and unaffected. The
    // multi-member empty-registry case hard-fails above with
    // `PseudonymRegistryEmpty` before reaching here.
    if !is_broadcast && send_routing_ids.is_empty() {
        crate::context::economy_logic::rollback_economy_ticket_inline(
            &mut state.governance,
            ticket,
        );
        state.membership.rollback_sequence_number(sender_did);
        return Ok(());
    }

    // Payment flow: authorize (hold) before action.
    let auth = match authorize_send_payment(state, deps, &context_id, sender_did).await {
        Ok(auth) => auth,
        Err(e) => {
            crate::context::economy_logic::rollback_economy_ticket_inline(
                &mut state.governance,
                ticket,
            );
            if !is_broadcast {
                state.membership.rollback_sequence_number(sender_did);
            }
            return Err(e);
        }
    };

    // Phase 2: encrypt + send.
    let phase2_result = encrypt_and_send(
        deps,
        broadcast_envelope,
        signing_key,
        &context_id,
        sender_did,
        payload,
        &recipients_data,
        sequence,
        source_provenance,
        &send_routing_ids,
        MessageType::Content,
    );
    if let Err(e) = phase2_result {
        // Void escrow + roll back ticket on send failure.
        if let Some(a) = auth {
            crate::context::economy_helpers::void_paid_action(state, deps, a, &context_id).await;
        }
        crate::context::economy_logic::rollback_economy_ticket_inline(
            &mut state.governance,
            ticket,
        );
        if !is_broadcast {
            state.membership.rollback_sequence_number(sender_did);
        }
        return Err(e);
    }

    // Phase 3: finalize, then capture escrow + commit ticket.
    //
    // ADR-049 §9 Class S (BLACK-001): the spending-nonce consume that
    // `enforce_send_economy` performed in Phase 1 mutated the actor-owned
    // `spending_nonce_tracker` — security-critical monotonic state that does
    // NOT survive an actor crash. It MUST be durably persisted (fail-closed)
    // BEFORE this paid send is acknowledged to the caller, exactly as the
    // structurally-identical TOOL-INVOKE path does in `reserve_tool_economy`.
    // A best-effort (coalesced) persist would let an actor crash in the ≤50ms
    // coalesce window roll the consume back, freshening the spending UCAN's
    // nonce after the caller already saw the send succeed — a replay /
    // double-spend window. `finalize_send` therefore persists fail-closed when
    // a spending nonce was committed for THIS send (mirroring the exact gating
    // `reserve_tool_economy` uses: `deducted_cost.is_some() &&
    // spending_ucan.is_some()`); on persist failure it returns an error and we
    // REVERSE the economy reservation (budget / velocity / rate-limit) and void
    // the escrow hold below — leaving the consumed nonce CONSUMED (the
    // fail-closed direction; un-consuming would re-open the replay window) and
    // surfacing the error so the caller does not observe a phantom success.
    // Non-spending / free sends keep the best-effort persist inside
    // `finalize_send` (the common path is not regressed).
    let spending_nonce_committed = deducted_cost.is_some() && spending_ucan.is_some();
    if let Err(e) = finalize_send(
        state,
        deps,
        &context_id,
        &context_id_bytes,
        sender_did,
        sequence,
        payload,
        signing_key,
        spending_nonce_committed,
        is_broadcast,
    ) {
        // Fail-closed persist of the Class-S nonce consume failed. Reverse the
        // economy reservation (the ticket is still alive — it is NOT committed
        // until finalize succeeds) and void the escrow hold. The sequence
        // rollback is INTENTIONALLY NOT performed here: `finalize_send` owns the
        // sequence rollback on all of its error exits (ADR-049 §9 round-5
        // regression fix). Rolling it back here too would revert the reserved
        // sequence twice (a +1 undone by −2 via `saturating_sub`), leaving the
        // counter one below correct. The consumed nonce is intentionally left
        // consumed (the fail-closed direction).
        if let Some(a) = auth {
            crate::context::economy_helpers::void_paid_action(state, deps, a, &context_id).await;
        }
        crate::context::economy_logic::rollback_economy_ticket_inline(
            &mut state.governance,
            ticket,
        );
        return Err(e);
    }

    let deducted_cost = crate::context::economy_logic::commit_economy_ticket(ticket);
    capture_send_payment(state, deps, auth, sender_did, &context_id, deducted_cost).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// 8. deliver_incoming (top-level, actor-shape)
// ---------------------------------------------------------------------------

/// Classified result of delivering one incoming envelope (§9.9.2).
///
/// Replaces the prior `Option<(Vec<u8>, String)>` return so the receive path
/// can distinguish three outcomes that callers must treat differently:
///
/// - [`DeliverOutcome::Application`] — a decrypted user message; the bridge
///   forwards `(plaintext, sender_did)` to the language binding's receive
///   channel.
/// - [`DeliverOutcome::Heartbeat`] — a suppression-detection heartbeat
///   (§9.9.2); processed internally, never surfaced as content, and the
///   bridge records it against the transport-layer `HeartbeatMonitor` to keep
///   the gap-detection baseline fresh. Distinct from `Handled` precisely so
///   the bridge knows to call `record_heartbeat_received`.
/// - [`DeliverOutcome::Handled`] — any other internally-processed message
///   (MLS Commit/Proposal, consistency checkpoint, pseudonym announcement, or
///   an out-of-order arrival buffered for later); no plaintext to surface and
///   nothing for the bridge to do.
#[derive(Debug)]
pub enum DeliverOutcome {
    /// Decrypted application message: `(plaintext, sender_did)`.
    Application((Vec<u8>, String)),
    /// A suppression-detection heartbeat was received and processed (§9.9.2).
    Heartbeat,
    /// An internal protocol message was processed; nothing to surface.
    Handled,
}

/// Delivers an incoming encrypted message from the relay to a context
/// (actor-shape). Returns a [`DeliverOutcome`] classifying the message:
/// [`DeliverOutcome::Application`] for user content, [`DeliverOutcome::Heartbeat`]
/// for a §9.9.2 heartbeat, or [`DeliverOutcome::Handled`] for management
/// messages and buffered out-of-order arrivals.
///
/// Sync — no await points in the actor body. The handler wraps the
/// call in `async {...}` so the per-call transport-timeout budget
/// still applies.
#[allow(clippy::too_many_lines)]
pub fn deliver_incoming(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    encrypted_blob: &[u8],
) -> Result<DeliverOutcome, ContextError> {
    let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);

    state::require_active(&state.handle)?;

    // Phase 1: read local member DID + access key (lock-free local_dids).
    let local_dids = deps.local_dids.load_full();
    let local_member_did = state
        .membership
        .member_dids()
        .find(|d| local_dids.contains(*d))
        .map(std::string::ToString::to_string)
        .ok_or_else(|| {
            ContextError::CryptoFailed("no local member found in this context".into())
        })?;
    let access_key = state
        .access
        .access_key_store
        .get(context_id, &local_member_did)
        .cloned();
    drop(local_dids);

    // Phase 2: open envelope (MLS + sender key + deserialize + integrity).
    let Some(opened_envelope) =
        decrypt_and_dispatch(deps, context_id, &context_id_bytes, encrypted_blob)?
    else {
        // MLS Commit / Proposal — processed internally by the crypto layer,
        // no inner envelope to classify.
        return Ok(DeliverOutcome::Handled);
    };

    let inner = opened_envelope.inner;
    let sender_did = opened_envelope.sender_did;

    // Cross-context injection defense.
    if inner.context_id != context_id {
        return Err(ContextError::CryptoFailed(format!(
            "inner envelope context_id mismatch: expected {context_id}, got {}",
            inner.context_id
        )));
    }

    // Credential-spoof defense.
    if inner.sender_did != sender_did {
        return Err(ContextError::CryptoFailed(format!(
            "inner envelope sender_did mismatch: MLS says {sender_did}, envelope says {}",
            inner.sender_did
        )));
    }

    // Recovery admin gate (only evaluated when message_type == Recovery).
    let sender_is_admin = if inner.message_type == MessageType::Recovery {
        state
            .role_state
            .member_has_capability(&sender_did, &Capability::ContextClose)
    } else {
        false
    };

    let ak = access_key.ok_or_else(|| {
        ContextError::CryptoFailed(format!(
            "no access key for {local_member_did} in context {context_id}"
        ))
    })?;
    let plaintext = verify_and_unwrap(
        &deps.key_resolver,
        &inner,
        &sender_did,
        context_id,
        &local_member_did,
        &ak,
        sender_is_admin,
    )?;

    // Consistency-checkpoint dispatch (§9.9.3, §23.7). A checkpoint message is
    // NOT application content: it is processed for equivocation detection and
    // MUST NOT advance the per-sender application sequence, so it is handled
    // here — after signature/integrity verification, before the anti-replay /
    // reorder sequence machinery — and returns `Handled`.
    if inner.message_type == MessageType::ConsistencyCheckpoint {
        return deliver_checkpoint_message(state, deps, context_id, &sender_did, &plaintext);
    }

    // Heartbeat dispatch (§9.9.2). A heartbeat is NOT application content: it
    // carries an empty payload and exists only as a liveness beacon for
    // suppression detection. Like a checkpoint, it is classified here — after
    // signature/integrity verification, before the anti-replay / reorder
    // sequence machinery — so it never advances the per-sender application
    // sequence. The bridge maps `Heartbeat` to a `record_heartbeat_received`
    // call against the transport-layer monitor so the gap-detection baseline
    // stays fresh. The verified plaintext is intentionally discarded.
    if inner.message_type == MessageType::Heartbeat {
        return Ok(DeliverOutcome::Heartbeat);
    }

    // Anti-replay + reorder buffer (§9.8.2, §9.8.5).
    let now_ms = deps.clock.now_millis();
    let sequence_check = validate_and_drain_timeouts(state, deps, context_id, &inner, now_ms)?;

    let is_local_sender = sender_did == local_member_did;

    match sequence_check {
        SequenceCheck::Expected => {
            let consumed_as_announcement = deliver_message_and_drain_buffered(
                state,
                deps,
                context_id,
                &context_id_bytes,
                &sender_did,
                &inner,
                &plaintext,
                is_local_sender,
            )?;
            if consumed_as_announcement {
                Ok(DeliverOutcome::Handled)
            } else {
                Ok(DeliverOutcome::Application((plaintext, sender_did)))
            }
        }
        SequenceCheck::Ahead { expected: _ } => {
            buffer_ahead_message(
                state,
                deps,
                context_id,
                &inner,
                &sender_did,
                &plaintext,
                now_ms,
            );
            Ok(DeliverOutcome::Handled)
        }
    }
}

/// Processes a received consistency-checkpoint message (§9.9.3, §23.7).
///
/// Deserializes the tagged [`CheckpointMessage`] from the verified plaintext,
/// confirms it carries the [`CHECKPOINT_PAYLOAD_TAG`] and that its embedded
/// `sender_did` matches the MLS-authenticated sender (a checkpoint claiming a
/// different author is a spoof), then hands it to
/// [`compare_remote_checkpoint`](crate::context::queries_helpers::compare_remote_checkpoint),
/// which verifies the checkpoint's own Ed25519 signature, compares Merkle roots
/// at equal event counts, and surfaces a
/// [`ContextEvent::EquivocationDetected`] when divergent.
///
/// Always returns [`DeliverOutcome::Handled`]: a checkpoint is never delivered
/// as application content and never advances the per-sender application
/// sequence.
///
/// # Errors
///
/// Returns [`ContextError::CryptoFailed`] if the payload is not a well-formed
/// tagged checkpoint or the embedded sender does not match, and propagates the
/// error from `compare_remote_checkpoint` (member-not-found or signature
/// failure).
fn deliver_checkpoint_message(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    sender_did: &str,
    plaintext: &[u8],
) -> Result<DeliverOutcome, ContextError> {
    let message: CheckpointMessage = rmp_serde::from_slice(plaintext).map_err(|e| {
        ContextError::CryptoFailed(format!("checkpoint message deserialization failed: {e}"))
    })?;
    if message.tag != CHECKPOINT_PAYLOAD_TAG {
        return Err(ContextError::CryptoFailed(
            "checkpoint message missing expected tag".into(),
        ));
    }
    // Bind the checkpoint author to the MLS-authenticated envelope sender: a
    // member may only publish checkpoints for their own DID. compare_remote_
    // checkpoint additionally verifies the checkpoint's own signature against
    // the resolved key for this DID, so a forged author cannot pass both gates.
    if message.checkpoint.sender_did.as_ref() != sender_did {
        return Err(ContextError::CryptoFailed(format!(
            "checkpoint sender_did {} does not match envelope sender {sender_did}",
            message.checkpoint.sender_did
        )));
    }

    // Equivocation detection (§9.9.3): verifies the checkpoint signature,
    // compares Merkle roots, and emits ContextEvent::EquivocationDetected into
    // the receive buffer when divergent (tier (a) of §23.7).
    crate::context::queries_helpers::compare_remote_checkpoint(
        state,
        deps,
        context_id,
        &message.checkpoint,
    )?;

    Ok(DeliverOutcome::Handled)
}

// ---------------------------------------------------------------------------
// 9. encrypt_and_send
// ---------------------------------------------------------------------------

/// Encrypts the payload and sends it via transport (Phase 2 of
/// [`send_message`]).
#[allow(clippy::too_many_arguments)]
pub fn encrypt_and_send(
    deps: &ActorDeps,
    broadcast_envelope: Option<BroadcastEnvelope>,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    context_id: &str,
    sender_did: &DID,
    payload: &[u8],
    recipients_data: &std::collections::HashMap<String, AccessKey>,
    sequence: u64,
    source_provenance: Option<&SourceContextInfo>,
    routing_ids: &[[u8; 32]],
    message_type: MessageType,
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
            &deps.clock,
            &deps.crypto,
            context_id,
            sender_did,
            payload,
            sk,
            recipients_data,
            sequence,
            source_provenance,
            message_type,
        )?;
        crate::metrics::record_encrypt_duration(encrypt_start.elapsed());
        result
    };
    // §9.10.4: fan-out — seal once, send to all routing IDs.
    //
    // Empty `routing_ids` is a valid no-op (e.g. a 1-member encrypted context
    // with no peer to fan out to). The send path raises
    // `PseudonymRegistryEmpty` for the suspicious "members > 1 but registry
    // empty" case before reaching here; an empty slice at this point means
    // there is legitimately nobody to address, so return success without
    // driving a transport failure.
    if routing_ids.is_empty() {
        return Ok(());
    }
    let mut last_err = None;
    let mut any_success = false;
    for rid in routing_ids {
        match deps.transport.send_message(rid, &encrypted) {
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
// 9b. send_checkpoint (§9.9.3, §23.7)
// ---------------------------------------------------------------------------

/// Broadcasts a signed [`ConsistencyCheckpoint`] to context peers so they can
/// compare Merkle roots at equal event counts and detect relay equivocation
/// (§9.9.3, §23.7).
///
/// The checkpoint is wrapped behind the [`CHECKPOINT_PAYLOAD_TAG`] magic tag,
/// `MessagePack`-encoded, and routed through the regular
/// [`encrypt_and_send`] envelope machinery with
/// [`MessageType::ConsistencyCheckpoint`]. The checkpoint already carries its
/// own `SCP-CHECKPOINT-V1:` signature; the outer envelope adds the usual
/// MLS + Ed25519 layers. This send is independent of the application content
/// sequence — it uses sequence `0`, and the receive path returns `Ok(None)`
/// before the content sequence tracker so a checkpoint never advances the
/// per-sender application sequence.
///
/// Routing mirrors the application-data send path:
/// - **Encrypted contexts** fan out to each known peer pseudonym routing ID.
///   With no peers yet known (lone member or pre-bootstrap), there is nobody
///   to inform and the call is a successful no-op.
/// - **Broadcast contexts** publish to the derivable broadcast routing ID
///   (`SHA-256(context_id)`); the checkpoint's `epoch` is `None` for broadcast
///   contexts per §23.16.1 (set by the caller via `build_checkpoint`).
///
/// # Errors
///
/// Returns [`ContextError::CryptoFailed`] if the checkpoint cannot be
/// serialized, or the underlying transport error from [`encrypt_and_send`] if
/// every fan-out send fails. Callers that publish checkpoints opportunistically
/// (the periodic-broadcast path in [`finalize_send`]) treat any error as
/// best-effort and MUST NOT roll back the originating send.
pub fn send_checkpoint(
    deps: &ActorDeps,
    state: &PerContextState,
    context_id: &str,
    sender_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
    checkpoint: &scp_event_log::checkpoint::ConsistencyCheckpoint,
) -> Result<(), ContextError> {
    let message = CheckpointMessage {
        tag: CHECKPOINT_PAYLOAD_TAG.to_owned(),
        checkpoint: checkpoint.clone(),
    };
    let payload = rmp_serde::to_vec_named(&message).map_err(|e| {
        ContextError::CryptoFailed(format!("checkpoint message serialization: {e}"))
    })?;

    // Routing parallels the application-data send path (§9.10.4): broadcast
    // contexts address the derivable broadcast RID; encrypted contexts fan out
    // to each known peer pseudonym. An empty encrypted routing set (no peers
    // known yet) is a legitimate no-op — there is simply nobody to inform.
    let (broadcast_envelope, recipients_data, routing_ids) = if state.broadcast_context.is_some() {
        let broadcast_rid = scp_protocol::context::broadcast_routing_id(context_id);
        // Broadcast contexts carry the checkpoint inside an encrypted inner
        // envelope addressed to the broadcast RID (the checkpoint exchange is
        // an MLS-management-style message, not author-keyed broadcast content).
        (None, std::collections::HashMap::new(), vec![broadcast_rid])
    } else {
        let peer_pseudonyms: Vec<[u8; 32]> = state
            .routing
            .peer_registry()
            .map(|reg| reg.values().copied().collect())
            .unwrap_or_default();
        (
            None,
            state.access.access_key_store.get_all(context_id),
            peer_pseudonyms,
        )
    };

    encrypt_and_send(
        deps,
        broadcast_envelope,
        Some(signing_key),
        context_id,
        sender_did,
        &payload,
        &recipients_data,
        // Checkpoints do not consume the application content sequence; the
        // receive path dispatches them before the sequence tracker.
        0,
        None,
        &routing_ids,
        MessageType::ConsistencyCheckpoint,
    )
}

// ---------------------------------------------------------------------------
// 9c. send_heartbeat (§9.9.2)
// ---------------------------------------------------------------------------

/// Sends a suppression-detection heartbeat envelope to context peers (§9.9.2).
///
/// A heartbeat is a minimal MLS application message with an EMPTY payload and
/// [`MessageType::Heartbeat`], routed through the regular [`encrypt_and_send`]
/// envelope machinery (MLS + sender-key + Ed25519 layers). It carries no user
/// content; its only purpose is to give peers a periodic liveness signal so the
/// transport-layer `HeartbeatMonitor` can detect relay suppression — if
/// heartbeats stop arriving from a recently-active participant, suppression is
/// suspected.
///
/// Like [`send_checkpoint`], the send is independent of the application content
/// sequence: it uses sequence `0`, and the receive path classifies it before
/// the content sequence tracker so a heartbeat never advances the per-sender
/// application sequence.
///
/// Routing mirrors the application-data send path (§9.10.4):
/// - **Encrypted contexts** fan out to each known peer pseudonym routing ID.
///   With no peers yet known (lone member or pre-bootstrap), there is nobody
///   to inform and the call is a successful no-op.
/// - **Broadcast contexts** publish to the derivable broadcast routing ID
///   (`SHA-256(context_id)`).
///
/// # Errors
///
/// Returns the underlying transport error from [`encrypt_and_send`] if every
/// fan-out send fails. The periodic bridge scheduler that drives this treats
/// any error as best-effort (a failed heartbeat is itself a suppression
/// signal, surfaced separately by the receiver's gap detection) and MUST NOT
/// tear down the subscription on a single failure.
pub fn send_heartbeat(
    deps: &ActorDeps,
    state: &PerContextState,
    context_id: &str,
    sender_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<(), ContextError> {
    // Send-authorization gates, mirroring `send_message` (§9.9.2 routes a
    // heartbeat through the same write path, so it must clear the same write
    // gates). Without these a member whose `MessagesWrite` capability was
    // suspended or revoked could keep asserting liveness on the write path,
    // and a heartbeat racing a context close could slip through after the
    // context is no longer active.
    //
    // 1. The context must be active. A send racing context-close is rejected.
    state::require_active(&state.handle)?;
    // 2. Capability check (broadcast contexts have no per-member write
    //    capability and address the public broadcast routing ID, exactly as in
    //    `send_message`). A suspended capability surfaces a distinct message so
    //    the scheduler's best-effort log is actionable.
    if state.broadcast_context.is_none()
        && !state
            .role_state
            .member_has_capability(sender_did.as_ref(), &Capability::MessagesWrite)
    {
        let is_suspended = state
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

    // Routing parallels the application-data and checkpoint send paths
    // (§9.10.4): broadcast contexts address the derivable broadcast RID;
    // encrypted contexts fan out to each known peer pseudonym. An empty
    // encrypted routing set (no peers known yet) is a legitimate no-op —
    // there is simply nobody to signal liveness to.
    let (broadcast_envelope, recipients_data, routing_ids) = if state.broadcast_context.is_some() {
        let broadcast_rid = scp_protocol::context::broadcast_routing_id(context_id);
        (None, std::collections::HashMap::new(), vec![broadcast_rid])
    } else {
        let peer_pseudonyms: Vec<[u8; 32]> = state
            .routing
            .peer_registry()
            .map(|reg| reg.values().copied().collect())
            .unwrap_or_default();
        (
            None,
            state.access.access_key_store.get_all(context_id),
            peer_pseudonyms,
        )
    };

    encrypt_and_send(
        deps,
        broadcast_envelope,
        Some(signing_key),
        context_id,
        sender_did,
        // Heartbeats carry NO user content — the empty payload is the whole
        // point: a minimal liveness beacon, padded by the envelope machinery.
        &[],
        &recipients_data,
        // Heartbeats do not consume the application content sequence; the
        // receive path classifies them before the sequence tracker.
        0,
        None,
        &routing_ids,
        MessageType::Heartbeat,
    )
}

// ---------------------------------------------------------------------------
// 10. authorize_send_payment
// ---------------------------------------------------------------------------

/// Authorizes escrow for send payment (Phase 1.5 of [`send_message`]).
pub async fn authorize_send_payment(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    sender_did: &DID,
) -> Result<Option<crate::context::economy_logic::PaidActionAuthorization>, ContextError> {
    crate::context::economy_helpers::authorize_paid_action(
        state,
        deps,
        scp_protocol::economy::types::PaidActionType::MessageSend,
        sender_did,
        context_id,
    )
    .await
}

// ---------------------------------------------------------------------------
// 11. capture_send_payment
// ---------------------------------------------------------------------------

/// Captures the escrow hold after a successful send (Phase 3 of
/// [`send_message`]). Best-effort: capture failure is logged + audited
/// but does NOT roll back budget (H8). On failure a
/// `PaymentCaptureFailed` event is appended (H19).
pub async fn capture_send_payment(
    state: &mut PerContextState,
    deps: &ActorDeps,
    auth: Option<crate::context::economy_logic::PaidActionAuthorization>,
    sender_did: &DID,
    context_id: &str,
    deducted_cost: Option<scp_protocol::economy::types::Amount>,
) {
    if let Some(a) = auth
        && let Err(e) = crate::context::economy_helpers::complete_paid_action(
            state, deps, a, sender_did, context_id,
        )
        .await
    {
        // H8: do NOT rollback budget — service was delivered.
        tracing::warn!(
            context_id,
            "payment capture failed after successful send: {e}"
        );
        // H19: append durable audit record.
        record_payment_capture_failure(
            state,
            deps,
            context_id,
            "send_message",
            sender_did,
            &e.to_string(),
            deducted_cost,
        );
    }
}

/// Append a `PaymentCaptureFailed` durable event log entry plus the
/// matching receive-buffer push. Actor-shape inline replacement for
/// `manager_methods::record_payment_capture_failure`.
#[allow(clippy::too_many_arguments)]
fn record_payment_capture_failure(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    action: &str,
    actor_did: &DID,
    error_msg: &str,
    cost: Option<scp_protocol::economy::types::Amount>,
) {
    let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);
    let payload_json = serde_json::json!({
        "action": action,
        "error": error_msg,
        "cost": cost.map(scp_protocol::economy::types::Amount::value),
    });
    let payload = scp_event_log::EventPayload {
        data: serde_json::to_vec(&payload_json).unwrap_or_default(),
    };
    if let Err(log_err) = deps.event_log.append_context_event_with_payload(
        &context_id_bytes,
        scp_event_log::EventType::PaymentCaptureFailed,
        actor_did.as_ref(),
        payload,
    ) {
        tracing::warn!(
            context_id,
            "failed to append PaymentCaptureFailed to event log: {log_err}"
        );
    }
    state.checkpoint_events_since += 1;
    let event = ContextEvent::PaymentCaptureFailed {
        action: action.to_owned(),
        actor_did: actor_did.clone(),
        error: error_msg.to_owned(),
        cost: cost.map(scp_protocol::economy::types::Amount::value),
    };
    emit_event_into(
        &mut state.receive_buffer,
        event,
        context_id,
        deps.event_tx.as_ref(),
    );
}

// ---------------------------------------------------------------------------
// 12. finalize_send
// ---------------------------------------------------------------------------

/// Appends the `MessageSent` event log entry and, on a log-append failure,
/// rolls the reserved per-sender sequence back (gated `!is_broadcast`) before
/// surfacing the error. This is the FIRST of [`finalize_send`]'s rollback
/// sites; it shares the single sequence-rollback ownership invariant documented
/// on [`finalize_send`] (the caller must not double-revert).
fn append_message_sent_or_rollback_sequence(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id_bytes: &[u8; 32],
    sender_did: &DID,
    is_broadcast: bool,
) -> Result<(), ContextError> {
    if let Err(e) = deps.event_log.append_context_event(
        context_id_bytes,
        scp_event_log::EventType::MessageSent,
        sender_did.as_ref(),
    ) {
        if !is_broadcast {
            state.membership.rollback_sequence_number(sender_did);
        }
        return Err(e);
    }
    Ok(())
}

/// Computes and caches the sender's participation record after a send.
/// Factored out of [`finalize_send`] to keep that function within the line
/// budget; pure bookkeeping with no error path (a missing Merkle root or a
/// zero-count record is simply not cached).
fn record_send_participation(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    sender_did: &DID,
    send_events: &[scp_event_log::Event],
    now: u64,
) {
    let send_merkle = deps
        .event_log
        .event_log_merkle_root(context_id_bytes)
        .unwrap_or([0u8; 32]);
    if !send_events.is_empty()
        && let Ok(record) = scp_protocol::trust::participation::compute_participation_record(
            send_events,
            sender_did.as_ref(),
            context_id,
            send_merkle,
            now,
        )
        && record.participation_count > 0
    {
        state
            .governance
            .participation_cache
            .insert(sender_did.to_string(), record);
    }
}

/// Pushes a `MessageSent` event, appends to the event log, runs
/// consequence enforcement, and persists. Actor-shape: no relock
/// dance — `state` is borrowed throughout.
///
/// Sync — no await points in the actor body. The caller (`send_message`)
/// stays `async` because it threads through escrow / transport awaits
/// before `finalize_send`.
///
/// `spending_nonce_committed` selects the ADR-049 §9 persistence class for the
/// final snapshot (BLACK-001): when `true` (a paid send committed a spending-
/// UCAN nonce in Phase 1 — `enforce_send_economy` mutated the actor-owned
/// `spending_nonce_tracker`, Class S monotonic state that does NOT survive an
/// actor crash), the persist is FAIL-CLOSED: a persist failure returns
/// [`ContextError::PersistenceFailed`] so the paid send is NOT acknowledged
/// while its nonce-consume is unpersisted, exactly mirroring the tool-invoke
/// path in `reserve_tool_economy`. When `false` (a free / non-spending send),
/// the persist stays best-effort (Class C) — the common path is not regressed.
///
/// # Sequence-rollback ownership (ADR-049 §9, round-9 leak fix)
///
/// `finalize_send` OWNS the per-sender sequence rollback on ALL of its error
/// exits — the FIRST `append_context_event` (delegated to
/// [`append_message_sent_or_rollback_sequence`]), the TTL early-return below,
/// and the final persist failure (in [`persist_finalized_send`]). The
/// `send_message` caller deliberately does NOT roll the sequence back when
/// `finalize_send` returns `Err`: doing so would double-revert, a `+1`
/// reservation undone by a `−2` via `saturating_sub`, leaving a per-sender gap
/// that a receiver reads as a `SequenceGapForceClose`. A broadcast publish
/// reserves NO per-sender sequence (`sequence` is 0 and `next_sequence_number`
/// was never called), so rolling back would spuriously decrement the
/// publisher's counter — every rollback is therefore gated on `!is_broadcast`.
/// The escrow hold + economy ticket are voided by the caller (they are still
/// alive — finalize did not commit them); only the sequence is the caller's
/// deferred responsibility, discharged here.
#[allow(clippy::too_many_arguments)]
pub fn finalize_send(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    sender_did: &DID,
    sequence: u64,
    payload: &[u8],
    signing_key: Option<&ed25519_dalek::SigningKey>,
    spending_nonce_committed: bool,
    is_broadcast: bool,
) -> Result<(), ContextError> {
    // M12: append event log BEFORE consequence evaluation; on failure roll the
    // reserved sequence back (round-9 leak fix — see the helper doc).
    append_message_sent_or_rollback_sequence(
        state,
        deps,
        context_id_bytes,
        sender_did,
        is_broadcast,
    )?;

    // Phase 3 reacquire-and-mutate is unnecessary in the actor model;
    // the actor owns state for the duration of the command. We DO
    // re-check the lifecycle state — a TTL expiry could land between
    // Phase 1 and finalize within the same command if the actor's TTL
    // arm fires (Phase 2A.9 wires this). For Phase 2A.7 this matches
    // the legacy contract: rollback the sequence number and exit.
    if state::require_active(&state.handle).is_err() {
        // Only encrypted sends reserved a sequence (broadcast publishes carry 0
        // and never call `next_sequence_number`) — broadcast must not roll back.
        if !is_broadcast {
            state.membership.rollback_sequence_number(sender_did);
        }
        // A spending-UCAN nonce committed in Phase 1 stays CONSUMED (a late TTL
        // expiry must not freshen it); persist it fail-closed so a crash before
        // coalesce cannot roll the consume back (ADR-049 §9 Class S).
        if spending_nonce_committed {
            persist_state_fail_closed(state, deps, context_id)?;
        }
        return Ok(());
    }

    let now = deps.clock.now_secs();
    let sent_event = ContextEvent::MessageSent {
        sender_did: sender_did.clone(),
        sequence_number: sequence,
        payload: payload.to_vec(),
    };
    emit_event_into(
        &mut state.receive_buffer,
        sent_event,
        context_id,
        deps.event_tx.as_ref(),
    );

    // Consequence enforcement.
    let send_events = crate::context::governance_logic::event_log_entries_for_consequences(
        &state.receive_buffer,
        context_id,
        now,
        &*deps.event_log,
    );
    let consequence_rules: Vec<ConsequenceRule> = state.governance.consequence_rules.clone();
    let send_triggered =
        evaluate_consequence_rules(&consequence_rules, &send_events, sender_did.as_ref(), now);
    {
        let mut split = crate::context::governance_logic::ConsequenceStateSplit {
            governance: &mut state.governance,
            role_state: &mut state.role_state,
            membership: &state.membership,
            receive_buffer: &mut state.receive_buffer,
            checkpoint_events_since: &mut state.checkpoint_events_since,
        };
        crate::context::governance_logic::enforce_triggered_consequences(
            &mut split,
            &crate::context::governance_logic::EnforceConsequencesCtx {
                context_id,
                member_did: sender_did,
                now,
                triggered: &send_triggered,
                rules: &consequence_rules,
                clock: &*deps.clock,
                event_log: &*deps.event_log,
                event_tx: deps.event_tx.as_ref(),
            },
        );
    }

    // Participation record (#1530).
    record_send_participation(
        state,
        deps,
        context_id,
        context_id_bytes,
        sender_did,
        &send_events,
        now,
    );

    // Checkpoint tracking (§9.9.3).
    state.checkpoint_events_since += 1;
    create_and_broadcast_checkpoint_if_due(state, deps, context_id, sender_did, signing_key, now);

    persist_finalized_send(
        state,
        deps,
        context_id,
        sender_did,
        spending_nonce_committed,
        is_broadcast,
    )
}

/// Creates a consistency checkpoint when due (§9.9.3 thresholds) and, when one
/// is produced, broadcasts it to peers via [`send_checkpoint`] so they can
/// detect relay equivocation (§23.7).
///
/// Factored out of [`finalize_send`] to keep that function within the clippy
/// line budget. The local retention (pushing into `state.checkpoints`) happens
/// inside `create_checkpoint_if_due`; the broadcast is **best-effort** — a
/// transport failure is logged but never rolls back the just-completed
/// application send, because the checkpoint is an independent
/// consistency-monitoring artifact, not part of the message's delivery
/// guarantee. A missing signing key (e.g. a context with no local custody)
/// skips checkpoint creation entirely.
fn create_and_broadcast_checkpoint_if_due(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    sender_did: &DID,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    now: u64,
) {
    let Some(sk) = signing_key else {
        return;
    };
    let broadcast_context_is_none = state.broadcast_context.is_none();
    let mls_epoch = state.epoch.mls_epoch;
    let due_checkpoint = crate::context::queries_helpers::create_checkpoint_if_due(
        context_id,
        broadcast_context_is_none,
        mls_epoch,
        &mut state.checkpoints,
        &mut state.checkpoint_events_since,
        &mut state.checkpoint_last_time_secs,
        sender_did,
        sk,
        now,
        &*deps.event_log,
    );
    if let Some(checkpoint) = due_checkpoint
        && let Err(e) = send_checkpoint(deps, state, context_id, sender_did, sk, &checkpoint)
    {
        tracing::warn!(
            context_id,
            error = %e,
            "failed to broadcast consistency checkpoint to peers (best-effort; \
             send not rolled back) (§9.9.3)"
        );
    }
}

/// Final persist step of [`finalize_send`], factored out so the success body
/// stays within the line budget. ADR-049 §9 Class S vs Class C: a paid send
/// that committed a spending-UCAN nonce MUST persist fail-closed (a best-effort
/// persist would let a crash in the ≤50ms coalesce window roll the consume back
/// after the caller saw success — replay / double-spend); the free path keeps
/// best-effort (not regressed).
///
/// This is the LAST of [`finalize_send`]'s rollback sites (the persist-failure
/// path); it shares the single sequence-rollback ownership invariant documented
/// on [`finalize_send`] (gated `!is_broadcast`, no caller double-revert).
fn persist_finalized_send(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    sender_did: &DID,
    spending_nonce_committed: bool,
    is_broadcast: bool,
) -> Result<(), ContextError> {
    if spending_nonce_committed {
        if let Err(e) = persist_state_fail_closed(state, deps, context_id) {
            if !is_broadcast {
                state.membership.rollback_sequence_number(sender_did);
            }
            return Err(e);
        }
    } else {
        persist_state_best_effort(state, deps, context_id);
    }
    Ok(())
}

/// Build the snapshot for `context_id` from owned actor state, threading in
/// the supervisor-owned MLS crypto state. Shared by the best-effort and
/// fail-closed persist paths. A crypto-export failure marks the snapshot
/// `needs_reconnect` (so restore fires the §23.11 reconnection pipeline)
/// rather than failing — the crypto state is Class M (crash-surviving), so a
/// transient export failure does not lose security state.
fn build_snapshot_for_persist(
    state: &PerContextState,
    deps: &ActorDeps,
    context_id: &str,
) -> crate::context::state::ContextSnapshot {
    let mut snapshot = build_snapshot_from_state(state);
    let ctx_id_bytes = scp_protocol::context::context_id_bytes(context_id);
    match deps.crypto.export_crypto_state(&ctx_id_bytes) {
        Ok(crypto_state) => snapshot.mls_crypto_state = crypto_state,
        Err(e) => {
            snapshot.needs_reconnect = true;
            snapshot.mls_crypto_state = Vec::new();
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to export MLS crypto state for persistence; \
                 snapshot marked needs_reconnect=true so restore \
                 fires the §23.11 reconnection pipeline"
            );
        }
    }
    snapshot
}

/// Best-effort persist of the current actor state. Mirrors the legacy
/// Phase 3 snapshot persistence path, but reads from actor-owned state.
///
/// Internal cross-module persistence helper — `pub` only so the sibling
/// `crate::context` dispatch modules can call it; not part of the SDK surface.
///
/// **Persistence class.** Use this ONLY for state whose ≤50ms coalesce-window
/// rollback is acceptable (ADR-049 §9 Class C — liveness/structural state and
/// the accepted soft anti-spam residual: velocity / earned-capacity). For
/// security-critical monotonic state that does NOT survive an actor crash
/// (Class S — spending-nonce consume, executed-proposals, downward-authorization
/// transitions), use [`persist_state_fail_closed`] so a persist failure returns
/// an error instead of silently acknowledging an unpersisted mutation.
pub fn persist_state_best_effort(state: &PerContextState, deps: &ActorDeps, context_id: &str) {
    let snapshot = build_snapshot_for_persist(state, deps, context_id);
    if let Err(e) = deps.persistence.persist_context(context_id, &snapshot) {
        crate::metrics::record_persistence_failure();
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to persist context snapshot"
        );
    }
}

/// Fail-closed sync persist of the current actor state (ADR-049 §9 Class S).
///
/// Persists synchronously and, on failure, returns
/// [`ContextError::PersistenceFailed`] instead of swallowing the error — so a
/// security-critical mutation (spending-nonce consume, executed-proposals,
/// downward-authorization transition) is NEVER acknowledged to a caller unless
/// it is durable. The respawn crash-safety invariant (ADR-049 §9) forbids
/// returning `Ok` for such a mutation when the persist did not land: a coalesced
/// (best-effort) acknowledgment would let an actor crash roll the mutation back,
/// re-opening a replay / re-spend / re-grant window after the caller already
/// observed success.
///
/// The failure metric is still recorded for observability.
///
/// Internal cross-module persistence helper — `pub` only so the sibling
/// `crate::context` dispatch modules can call it; not part of the SDK surface.
///
/// # Errors
///
/// Returns [`ContextError::PersistenceFailed`] if the underlying
/// `persist_context` write fails.
pub fn persist_state_fail_closed(
    state: &PerContextState,
    deps: &ActorDeps,
    context_id: &str,
) -> Result<(), ContextError> {
    let snapshot = build_snapshot_for_persist(state, deps, context_id);
    deps.persistence
        .persist_context(context_id, &snapshot)
        .map_err(|e| {
            crate::metrics::record_persistence_failure();
            tracing::error!(
                context_id = %context_id,
                error = %e,
                "fail-closed persist of security-critical state failed; \
                 operation rejected (ADR-049 §9 Class S)"
            );
            ContextError::PersistenceFailed(format!(
                "fail-closed persist failed for context '{context_id}': {e}"
            ))
        })
}

#[allow(clippy::too_many_lines)]
pub fn build_snapshot_from_state(
    state: &PerContextState,
) -> crate::context::state::ContextSnapshot {
    use crate::context::state::{GovernanceState, VelocityTrackerSnapshot};
    use scp_protocol::context::ContextState;

    // ADR-049 §9 (white-hat P2): exhaustively destructure `GovernanceState` so a
    // NEW governance field forces a conscious persist decision AT COMPILE TIME.
    // Without this bind, a freshly-added field is invisible to both this builder
    // and the field-round-trip test — silently dropped from the snapshot and
    // lost across an actor crash. Every field is bound below: persisted fields
    // are threaded into the snapshot; genuinely-transient fields are `_`-prefixed
    // WITH a justification. Adding a field to `GovernanceState` will fail to
    // compile here until the author decides which bucket it belongs to.
    let GovernanceState {
        // --- Persisted: threaded into ContextSnapshot below. ---
        // `engine` is persisted via `governance_model_config: Some(engine.model_config())`.
        engine: _engine_persisted_as_model_config,
        executed_proposals: _executed_proposals,
        approved_proposals: _approved_proposals,
        next_proposal_seq: _next_proposal_seq,
        freeze: _freeze,
        threshold_signers: _threshold_signers,
        threshold_value: _threshold_value,
        pending_ceiling_modification: _pending_ceiling_modification,
        pending_economic_policy_change: _pending_economic_policy_change,
        registered_tools: _registered_tools,
        tool_interfaces: _tool_interfaces,
        pruning_policy: _pruning_policy,
        economic_policy: _economic_policy,
        budget_tracker: _budget_tracker,
        consequence_rules: _consequence_rules,
        velocity_tracker: _velocity_tracker,
        participation_cache: _participation_cache,
        cooldown_until: _cooldown_until,
        message_pricing: _message_pricing,
        hard_rate_limit: _hard_rate_limit,
        spending_nonce_tracker: _spending_nonce_tracker,
        revoked_spending_ucan_cids: _revoked_spending_ucan_cids,
        proposal_timestamps: _proposal_timestamps,
        // --- Transient: deliberately NOT persisted (rebuilt at restore). ---
        // `timeout_task`: governance-timer handle, re-installed by the actor
        // registry on respawn (no durable identity to preserve).
        timeout_task: _timeout_task_transient,
        // `deadlock`: per-context deadlock-detection scratch state, recomputed
        // from the live proposal set after restore.
        deadlock: _deadlock_transient,
        // `last_known_members`: departure-detection cache for the timeout loop;
        // re-seeded from `membership` on the next tick.
        last_known_members: _last_known_members_transient,
        // `pending_epoch_resets`: drained each timeout tick; an in-flight reset
        // is re-driven by the member, not replayed from a snapshot.
        pending_epoch_resets: _pending_epoch_resets_transient,
    } = &state.governance;

    let context_state_value = state
        .handle
        .try_read_state()
        .unwrap_or(ContextState::Active);
    let ttl_remaining_secs = state.ttl.timer.remaining_secs();
    let grace_entries = state.epoch.grace_store.to_grace_entries();

    crate::context::state::ContextSnapshot {
        context_id: state.handle.context_id().to_owned(),
        state: context_state_value,
        context_params: state.handle.params().clone(),
        membership: state.membership.clone(),
        role_state: state.role_state.clone(),
        event_log_merkle_root: [0u8; 32],
        executed_proposals: state
            .governance
            .executed_proposals
            .keys()
            .copied()
            .collect(),
        ttl_remaining_secs,
        registered_tools: state.governance.registered_tools.clone(),
        read_exclusion_list: state.access.read_exclusion_list.clone(),
        tool_interfaces: state.governance.tool_interfaces.clone(),
        threshold_signers: state.governance.threshold_signers.clone(),
        threshold_value: state.governance.threshold_value,
        pruning_policy: state.governance.pruning_policy.clone(),
        governance_model_config: Some(state.governance.engine.model_config()),
        economic_policy: state.governance.economic_policy.clone(),
        budget_tracker: state.governance.budget_tracker.clone(),
        approved_proposals: state.governance.approved_proposals.clone(),
        next_proposal_seq: state.governance.next_proposal_seq,
        governance_freeze: state.governance.freeze,
        pending_ceiling_modification: state.governance.pending_ceiling_modification.clone(),
        pending_economic_policy_change: state.governance.pending_economic_policy_change.clone(),
        mls_epoch: state.epoch.mls_epoch,
        epoch_coordination_records: state.epoch.coordinator.records().to_vec(),
        grace_entries,
        needs_reconnect: state.epoch.needs_reconnect,
        mls_crypto_state: Vec::new(),
        migration_state: state.migration_state.clone(),
        access_key_store: state.access.access_key_store.clone(),
        consequence_rules: state.governance.consequence_rules.clone(),
        participation_cache: state.governance.participation_cache.clone(),
        velocity_tracker: Some(state.governance.velocity_tracker.window_secs()),
        velocity_tracker_state: Some(VelocityTrackerSnapshot {
            window_secs: state.governance.velocity_tracker.window_secs(),
            entries: state.governance.velocity_tracker.snapshot_entries(),
        }),
        cooldown_until: state.governance.cooldown_until.clone(),
        proposal_timestamps: state.governance.proposal_timestamps.clone(),
        message_pricing: state.governance.message_pricing.clone(),
        hard_rate_limit_config: Some(state.governance.hard_rate_limit.config().clone()),
        hard_rate_limit_state: state.governance.hard_rate_limit.snapshot_entries(),
        spending_nonce_tracker_state: state.governance.spending_nonce_tracker.snapshot_entries(),
        revoked_spending_ucan_cids: state.governance.revoked_spending_ucan_cids.clone(),
        pending_commits: state.pending_commits.clone(),
        commit_fault: state.commit_fault.clone(),
        checkpoint_events_since: state.checkpoint_events_since,
        checkpoint_last_time_secs: state.checkpoint_last_time_secs,
        generation: state.generation,
        // §9.10.4: persist the routing axis verbatim. `ContextRouting` is the
        // single shared type between live state and the serialized snapshot,
        // so no field-by-field translation is needed.
        routing: state.routing.clone(),
        // ADR-049 §9 Class S (line 144): persist the staged saga slot through
        // its sanctioned serialization mirror so a Prepare's staged evidence
        // survives an actor crash. See [`saga_pending_snapshot`].
        saga_pending: saga_pending_snapshot(state),
        xctx_committed_outputs: xctx_committed_outputs_snapshot(state),
        xctx_committed_invocations: xctx_committed_invocations_snapshot(state),
        // ADR-049 §9 Class S (spec §6.2.4): persist the caller-side durable
        // reservation reversal records so a `PreparingB`-window crash can reverse
        // the caller deduction + void the escrow without the in-memory carrier.
        xctx_caller_reservations: xctx_caller_reservations_snapshot(state),
        xctx_nonce_dedup: xctx_nonce_dedup_snapshot(state),
    }
}

/// Project the actor-side `saga_pending` map onto its serializable Class-S
/// snapshot mirror (ADR-049 §9 line 144; spec §5.15.8 / §6.2.4 Prepare).
///
/// The live [`SagaPreparedState`](crate::context::supervisor::saga_prepared_state::SagaPreparedState)
/// enum keeps the §9.4.3 non-derive barrier, so the snapshot carries the
/// sanctioned
/// [`SagaPreparedStateSnapshot`](crate::context::supervisor::saga_prepared_state::SagaPreparedStateSnapshot)
/// mirror instead. Every snapshot builder (the canonical one here plus the
/// broadcast / ttl-close / trust-recovery / manager copies) routes through
/// THIS one helper, so a saga in flight is dropped by none of them.
#[must_use]
pub(in crate::context) fn saga_pending_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<
    crate::context::supervisor::saga_journal::SagaId,
    crate::context::supervisor::saga_prepared_state::SagaPreparedStateSnapshot,
> {
    use crate::context::supervisor::saga_prepared_state::SagaPreparedStateSnapshot;
    state
        .saga_pending
        .iter()
        .map(|(id, prepared)| {
            (
                id.clone(),
                SagaPreparedStateSnapshot::from_prepared(prepared),
            )
        })
        .collect()
}

/// Build the Class-S snapshot projection of the actor's COMMITTED
/// cross-context tool-invocation captures (spec §6.2.4 "Exactly-once
/// execution with durable output capture"; ADR-049 §9). The live
/// [`CommittedToolInvocation`](crate::context::supervisor::saga_prepared_state::CommittedToolInvocation)
/// carries no §9.4.3 bearer bytes (public receipt + output), so — unlike
/// [`saga_pending_snapshot`] — the snapshot stores it directly via `Clone`.
/// Used at every snapshot builder so a crash between Commit-B capture and the
/// next coalesced write cannot lose the durable output (which would re-invoke
/// the tool on replay).
pub(in crate::context) fn xctx_committed_outputs_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<
    crate::context::supervisor::saga_journal::SagaId,
    crate::context::supervisor::saga_prepared_state::CommittedToolInvocation,
> {
    state.xctx_committed_outputs.clone()
}

/// Build the Class-S snapshot projection of the actor's caller-side (A-owned)
/// COMMITTED cross-context tool-invocation witness set (spec §6.2.4 "Commit",
/// caller side; §17.16.4 crash recovery; ADR-049 §9). The live
/// [`PerContextState::xctx_committed_invocations`](crate::context::actor::state::PerContextState::xctx_committed_invocations)
/// is a `{SagaId}` idempotency-witness set carrying no §9.4.3 bearer bytes, so —
/// like [`xctx_committed_outputs_snapshot`] — the snapshot stores it directly
/// via `Clone`. Exists so EVERY snapshot builder projects this Class-S saga
/// field through ONE helper, exactly like its siblings
/// (`saga_pending_snapshot` / `xctx_committed_outputs_snapshot` /
/// `xctx_caller_reservations_snapshot` / `xctx_nonce_dedup_snapshot`) — no
/// Class-S saga field is centralized by convention alone. Without persisting it,
/// a crash that rolled the witness back behind an acked Commit-A would
/// double-settle the caller escrow on replay.
pub(in crate::context) fn xctx_committed_invocations_snapshot(
    state: &PerContextState,
) -> std::collections::HashSet<crate::context::supervisor::saga_journal::SagaId> {
    state.xctx_committed_invocations.clone()
}

/// Build the Class-S snapshot projection of the actor's caller-side durable
/// reservation reversal records (spec §6.2.4 "Reservation release on every
/// terminal path"; §17.16.4 crash recovery; ADR-049 §9). The live
/// [`PerContextState::xctx_caller_reservations`](crate::context::actor::state::PerContextState::xctx_caller_reservations)
/// is a `{SagaId → CallerReservationRecord}` map whose values carry no §9.4.3
/// bearer bytes (public economy metadata), so — like
/// [`xctx_committed_invocations_snapshot`] — the snapshot stores it directly via
/// `Clone`. Exists so EVERY snapshot builder projects this Class-S saga field
/// through ONE helper, exactly like its siblings (`saga_pending_snapshot` /
/// `xctx_committed_outputs_snapshot` / `xctx_committed_invocations_snapshot` /
/// `xctx_nonce_dedup_snapshot`) — no Class-S saga field is centralized by
/// convention alone. Without persisting it, a `PreparingB`-window crash could
/// never reverse the caller's deduction or void the escrow from the durable
/// record, durably over-charging the caller.
pub(in crate::context) fn xctx_caller_reservations_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<
    crate::context::supervisor::saga_journal::SagaId,
    crate::context::supervisor::saga_prepared_state::CallerReservationRecord,
> {
    state.xctx_caller_reservations.clone()
}

/// Build the Class-S snapshot projection of the actor's B-owned cross-context
/// nonce-dedup cache (spec §6.2.4 "Freshness / anti-replay"; ADR-049 §9). The
/// live [`NonceDedup`](scp_protocol::crypto::sender_keys::NonceDedup) projects
/// to a plain `{nonce → first-seen secs}` map via `entries()`. Persisting it at
/// every snapshot builder makes the replay-protection cache CRASH-SURVIVING: a
/// restart no longer reopens the 5-minute window for a fresh-`SagaId` replay of
/// a `CrossContextToolInvoke` (BLACK-624-01). Same-node restore rehydrates it;
/// cross-node export/import drops it to empty (B's freshness state has no
/// authority on a foreign node).
pub(in crate::context) fn xctx_nonce_dedup_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<[u8; 16], u64> {
    state.xctx_nonce_dedup.entries()
}

// ---------------------------------------------------------------------------
// 13. decrypt_and_dispatch
// ---------------------------------------------------------------------------

/// Decrypts an incoming envelope and dispatches management/control
/// messages.
pub fn decrypt_and_dispatch(
    deps: &ActorDeps,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    encrypted_blob: &[u8],
) -> Result<Option<scp_protocol::context::builder::OpenedEnvelope>, ContextError> {
    let decrypt_start = std::time::Instant::now();
    let open_result = deps.crypto.open(context_id_bytes, encrypted_blob)?;
    crate::metrics::record_decrypt_duration(decrypt_start.elapsed());

    match open_result {
        scp_protocol::context::builder::OpenResult::Application(env) => Ok(Some(*env)),
        scp_protocol::context::builder::OpenResult::Control => Ok(None),
        scp_protocol::context::builder::OpenResult::Management {
            sender_did,
            payload,
        } => {
            tracing::debug!(sender_did = %sender_did, context_id = %context_id, "received MLS-wrapped management message");
            deps.crypto
                .process_incoming_sender_key(context_id_bytes, &sender_did, &payload)?;
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// 14. validate_and_drain_timeouts
// ---------------------------------------------------------------------------

/// Validates timestamp and sequence, then drains timed-out gaps.
pub fn validate_and_drain_timeouts(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    inner: &scp_protocol::envelope::inner::InnerEnvelope,
    now_ms: u64,
) -> Result<SequenceCheck, ContextError> {
    // Timestamp validation first.
    let tv = scp_protocol::envelope::validation::TimestampValidator::default();
    tv.validate(inner, now_ms)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    // Sequence check: replay detection + gap detection (§9.8.5).
    let check = state
        .sequence_tracker
        .validate(inner)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    // Drain timed-out gaps.
    let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);
    let timed_out = state
        .reorder_buffer
        .drain_timed_out(now_ms, &state.sequence_tracker);
    for (gap_info, messages) in timed_out {
        let gap_event = ContextEvent::SequenceGapDetected {
            sender_did: DID(gap_info.sender_did.clone()),
            expected_sequence: gap_info.expected_sequence,
            first_delivered_sequence: gap_info.first_buffered_sequence,
            reason: format!("{:?}", gap_info.reason),
        };
        emit_event_into(
            &mut state.receive_buffer,
            gap_event,
            context_id,
            deps.event_tx.as_ref(),
        );
        for msg in &messages {
            // Re-check membership and capability.
            if !state.membership.contains(&msg.sender_did)
                || !state
                    .role_state
                    .member_has_capability(&msg.sender_did, &Capability::MessagesWrite)
            {
                continue;
            }
            state.sequence_tracker.advance(
                &msg.inner.context_id,
                &msg.sender_did,
                msg.inner.sequence,
                msg.inner.timestamp,
            );
            let event_name = deliver_plaintext_or_announcement(
                state,
                &msg.sender_did,
                &msg.plaintext,
                context_id,
                deps.event_tx.as_ref(),
            );
            run_buffered_post_delivery(
                state,
                context_id,
                &context_id_bytes,
                &msg.sender_did,
                event_name,
                &*deps.clock,
                &*deps.event_log,
                deps.event_tx.as_ref(),
            );
        }
    }

    Ok(check)
}

// ---------------------------------------------------------------------------
// 15. buffer_ahead_message
// ---------------------------------------------------------------------------

/// Buffers an out-of-order message that arrived ahead of expected
/// sequence. Force-delivers oldest gap on overflow.
pub fn buffer_ahead_message(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    inner: &scp_protocol::envelope::inner::InnerEnvelope,
    sender_did: &str,
    plaintext: &[u8],
    now_ms: u64,
) {
    let buffered_msg = scp_protocol::envelope::validation::BufferedMessage {
        inner: inner.clone(),
        sender_did: sender_did.to_owned(),
        plaintext: plaintext.to_vec(),
        received_at: now_ms,
    };

    if let Some((mut gap_info, messages)) = state.reorder_buffer.buffer(buffered_msg) {
        let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);
        let expected = state
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
        emit_event_into(
            &mut state.receive_buffer,
            gap_event,
            context_id,
            deps.event_tx.as_ref(),
        );

        for msg in &messages {
            if !state.membership.contains(&msg.sender_did)
                || !state
                    .role_state
                    .member_has_capability(&msg.sender_did, &Capability::MessagesWrite)
            {
                continue;
            }
            state.sequence_tracker.advance(
                &msg.inner.context_id,
                &msg.sender_did,
                msg.inner.sequence,
                msg.inner.timestamp,
            );
            let event_name = deliver_plaintext_or_announcement(
                state,
                &msg.sender_did,
                &msg.plaintext,
                context_id,
                deps.event_tx.as_ref(),
            );
            run_buffered_post_delivery(
                state,
                context_id,
                &context_id_bytes,
                &msg.sender_did,
                event_name,
                &*deps.clock,
                &*deps.event_log,
                deps.event_tx.as_ref(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 16. deliver_message_and_drain_buffered
// ---------------------------------------------------------------------------

/// Delivers a message that is in sequence order, advances the tracker,
/// pushes the event, and drains any consecutive buffered messages.
/// Returns `true` when the message was consumed as a pseudonym
/// announcement (internal protocol message).
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
pub fn deliver_message_and_drain_buffered(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    sender_did: &str,
    inner: &scp_protocol::envelope::inner::InnerEnvelope,
    plaintext: &[u8],
    skip_velocity: bool,
) -> Result<bool, ContextError> {
    let sender_did_obj = DID(sender_did.to_owned());

    state::require_active(&state.handle)?;

    if !state.membership.contains(sender_did) {
        return Err(ContextError::MemberNotFound(format!(
            "sender {sender_did} is not a member of this context"
        )));
    }
    if !state
        .role_state
        .member_has_capability(sender_did, &Capability::MessagesWrite)
    {
        let is_suspended = state
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

    // §9.10.4: run the shared announcement-ingest validator. The direct path
    // maps a rejection to a typed `Err(PermissionDenied)` (there IS a caller to
    // surface it to), and on success runs the in-order follow-up below.
    match ingest_pseudonym_announcement(
        state,
        sender_did,
        plaintext,
        context_id,
        deps.event_tx.as_ref(),
    ) {
        AnnouncementOutcome::Rejected(reason) => {
            return Err(ContextError::PermissionDenied(reason.to_owned()));
        }
        AnnouncementOutcome::NotAnnouncement => {
            // Fall through to the normal-message delivery path below.
        }
        AnnouncementOutcome::Recorded => {
            // Recorded + emitted by the shared validator (registry insert +
            // `ContextEvent::PseudonymAnnounced` buffer signal). The remaining
            // follow-up — sequence-tracker advance, reorder-buffer drain,
            // velocity, and consequence evaluation — is specific to the in-order
            // direct path and runs here only. There is NO durable Merkle append:
            // a received announcement is a §9.10.4 routing-bootstrap signal, not a
            // convergent event (per-receiver arrival order; WASM never appends on
            // receive), so appending it would false-positive §9.9.3 equivocation
            // detection — the same reason received application messages are
            // buffer-only.
            state
                .sequence_tracker
                .advance(context_id, sender_did, inner.sequence, inner.timestamp);
            let next_expected = inner.sequence.saturating_add(1);
            let consecutive =
                state
                    .reorder_buffer
                    .drain_consecutive(context_id, sender_did, next_expected);
            for msg in &consecutive {
                if !state.membership.contains(&msg.sender_did)
                    || !state
                        .role_state
                        .member_has_capability(&msg.sender_did, &Capability::MessagesWrite)
                {
                    continue;
                }
                state.sequence_tracker.advance(
                    &msg.inner.context_id,
                    &msg.sender_did,
                    msg.inner.sequence,
                    msg.inner.timestamp,
                );
                let event_name = deliver_plaintext_or_announcement(
                    state,
                    &msg.sender_did,
                    &msg.plaintext,
                    context_id,
                    deps.event_tx.as_ref(),
                );
                run_buffered_post_delivery(
                    state,
                    context_id,
                    context_id_bytes,
                    &msg.sender_did,
                    event_name,
                    &*deps.clock,
                    &*deps.event_log,
                    deps.event_tx.as_ref(),
                );
            }

            let now = deps.clock.now_secs();
            if !skip_velocity {
                state
                    .governance
                    .velocity_tracker
                    .record_message(&DID(sender_did.to_owned()), now);
            }
            let consequence_rules: Vec<ConsequenceRule> =
                state.governance.consequence_rules.clone();
            if !consequence_rules.is_empty() {
                let recv_events =
                    crate::context::governance_logic::event_log_entries_for_consequences(
                        &state.receive_buffer,
                        context_id,
                        now,
                        &*deps.event_log,
                    );
                let recv_triggered =
                    evaluate_consequence_rules(&consequence_rules, &recv_events, sender_did, now);
                let recv_member_did = DID(sender_did.to_owned());
                let mut split = crate::context::governance_logic::ConsequenceStateSplit {
                    governance: &mut state.governance,
                    role_state: &mut state.role_state,
                    membership: &state.membership,
                    receive_buffer: &mut state.receive_buffer,
                    checkpoint_events_since: &mut state.checkpoint_events_since,
                };
                crate::context::governance_logic::enforce_triggered_consequences(
                    &mut split,
                    &crate::context::governance_logic::EnforceConsequencesCtx {
                        context_id,
                        member_did: &recv_member_did,
                        now,
                        triggered: &recv_triggered,
                        rules: &consequence_rules,
                        clock: &*deps.clock,
                        event_log: &*deps.event_log,
                        event_tx: deps.event_tx.as_ref(),
                    },
                );
            }
            state.checkpoint_events_since += 1;

            return Ok(true);
        }
    }

    // Normal message: advance tracker + deliver.
    state
        .sequence_tracker
        .advance(context_id, sender_did, inner.sequence, inner.timestamp);
    let recv_event = ContextEvent::MessageReceived {
        sender_did: sender_did_obj,
        payload: plaintext.to_vec(),
    };
    emit_event_into(
        &mut state.receive_buffer,
        recv_event,
        context_id,
        deps.event_tx.as_ref(),
    );

    // Drain consecutive buffered (§9.8.5).
    let next_expected = inner.sequence.saturating_add(1);
    let consecutive = state
        .reorder_buffer
        .drain_consecutive(context_id, sender_did, next_expected);
    for msg in &consecutive {
        if !state.membership.contains(&msg.sender_did)
            || !state
                .role_state
                .member_has_capability(&msg.sender_did, &Capability::MessagesWrite)
        {
            continue;
        }
        state.sequence_tracker.advance(
            &msg.inner.context_id,
            &msg.sender_did,
            msg.inner.sequence,
            msg.inner.timestamp,
        );
        let event_name = deliver_plaintext_or_announcement(
            state,
            &msg.sender_did,
            &msg.plaintext,
            context_id,
            deps.event_tx.as_ref(),
        );
        run_buffered_post_delivery(
            state,
            context_id,
            context_id_bytes,
            &msg.sender_did,
            event_name,
            &*deps.clock,
            &*deps.event_log,
            deps.event_tx.as_ref(),
        );
    }

    // §9.9.3: received application messages are NOT appended to the durable
    // Merkle event log. A MessageReceived leaf is minted by the receiver and
    // is not authenticated by the sender, so two honest receivers would
    // compute divergent roots for the same context and false-positive
    // equivocation detection. The receive buffer (in-memory, SDK-observable)
    // still records the message; consequence evaluation reads it from there.

    // H16: defense-in-depth velocity + consequence eval on receive.
    let now = deps.clock.now_secs();
    if !skip_velocity {
        state
            .governance
            .velocity_tracker
            .record_message(&DID(sender_did.to_owned()), now);
    }
    let consequence_rules: Vec<ConsequenceRule> = state.governance.consequence_rules.clone();
    if !consequence_rules.is_empty() {
        let recv_events = crate::context::governance_logic::event_log_entries_for_consequences(
            &state.receive_buffer,
            context_id,
            now,
            &*deps.event_log,
        );
        let recv_triggered =
            evaluate_consequence_rules(&consequence_rules, &recv_events, sender_did, now);
        let recv_member_did = DID(sender_did.to_owned());
        let mut split = crate::context::governance_logic::ConsequenceStateSplit {
            governance: &mut state.governance,
            role_state: &mut state.role_state,
            membership: &state.membership,
            receive_buffer: &mut state.receive_buffer,
            checkpoint_events_since: &mut state.checkpoint_events_since,
        };
        crate::context::governance_logic::enforce_triggered_consequences(
            &mut split,
            &crate::context::governance_logic::EnforceConsequencesCtx {
                context_id,
                member_did: &recv_member_did,
                now,
                triggered: &recv_triggered,
                rules: &consequence_rules,
                clock: &*deps.clock,
                event_log: &*deps.event_log,
                event_tx: deps.event_tx.as_ref(),
            },
        );
    }

    state.checkpoint_events_since += 1;
    crate::metrics::record_message_received();

    Ok(false)
}

// ---------------------------------------------------------------------------
// 17. send_pseudonym_announcement
// ---------------------------------------------------------------------------

/// Sends a pseudonym announcement MLS message so other members can map
/// the announcing member's DID to their per-context pseudonym routing
/// ID. Best-effort — internal log on transport / serialization failure.
pub async fn send_pseudonym_announcement(
    state: &mut PerContextState,
    deps: &ActorDeps,
    handle: &ContextHandle,
    sender_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
) {
    let context_id = handle.context_id().to_owned();
    let Some(pseudonym) = state.routing.local_pseudonym() else {
        return;
    };
    let announcement = state::PseudonymAnnouncement {
        tag: state::PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
        member_did: sender_did.as_ref().to_owned(),
        pseudonym,
    };
    let Ok(payload) = rmp_serde::to_vec_named(&announcement) else {
        tracing::warn!(
            context_id = %context_id,
            "failed to serialize pseudonym announcement"
        );
        return;
    };
    if let Err(e) = send_message(
        state,
        deps,
        handle,
        sender_did,
        &payload,
        Some(signing_key),
        None,
        None,
    )
    .await
    {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to send pseudonym announcement — peers cannot address this member until it re-announces (no shared-RID fallback for application data)"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod pseudonym_routing_tests {
    use super::{
        is_pseudonym_announcement_payload, is_reserved_pseudonym, pseudonym_collides_with_other_did,
    };
    use crate::context::state::{PSEUDONYM_ANNOUNCEMENT_TAG, PseudonymAnnouncement};
    use scp_identity::DID;
    use std::collections::HashMap;

    const CTX: &str = "ctx-pseudonym-routing-tests";

    fn announcement_bytes(member_did: &str, pseudonym: [u8; 32]) -> Vec<u8> {
        let ann = PseudonymAnnouncement {
            tag: PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
            member_did: member_did.to_owned(),
            pseudonym,
        };
        rmp_serde::to_vec_named(&ann).expect("serialize announcement")
    }

    /// §9.10.4: the shared `context_routing_id` is a RESERVED value — a member
    /// must not be able to announce it as their own pseudonym, because honest
    /// senders fan app-data out to announced pseudonyms and the shared RID is
    /// relay-derivable. This is the type-level proof that the deleted
    /// `shared_rid` fallback cannot be reintroduced through an announcement.
    #[test]
    fn shared_context_routing_id_is_reserved() {
        let shared = scp_protocol::context::context_routing_id(CTX);
        assert!(
            is_reserved_pseudonym(&shared, CTX),
            "shared context routing id must be rejected as a pseudonym value"
        );
    }

    #[test]
    fn zero_and_broadcast_routing_ids_are_reserved() {
        assert!(
            is_reserved_pseudonym(&[0u8; 32], CTX),
            "zero sentinel reserved"
        );
        let broadcast = scp_protocol::context::broadcast_routing_id(CTX);
        assert!(
            is_reserved_pseudonym(&broadcast, CTX),
            "broadcast routing id reserved"
        );
    }

    #[test]
    fn honest_pseudonym_is_not_reserved() {
        // A raw Ed25519-public-key-shaped value (non-zero, not a derivable RID).
        let honest = [7u8; 32];
        assert!(
            !is_reserved_pseudonym(&honest, CTX),
            "an ordinary pseudonym must be accepted"
        );
    }

    #[test]
    fn cross_did_collision_detected_same_did_allowed() {
        let mut registry: HashMap<DID, [u8; 32]> = HashMap::new();
        let alice = DID("did:key:alice".to_owned());
        let bob = DID("did:key:bob".to_owned());
        let rid = [9u8; 32];
        registry.insert(alice.clone(), rid);

        // Bob claiming Alice's routing ID is a cross-DID collision.
        assert!(
            pseudonym_collides_with_other_did(&registry, &bob, &rid),
            "a different DID claiming an existing routing ID is a collision"
        );
        // Alice re-announcing her OWN routing ID (key rotation rebroadcast) is fine.
        assert!(
            !pseudonym_collides_with_other_did(&registry, &alice, &rid),
            "same-DID re-announce is not a collision"
        );
    }

    #[test]
    fn announcement_classifier_matches_only_tagged_payloads() {
        let tagged = announcement_bytes("did:key:alice", [3u8; 32]);
        assert!(
            is_pseudonym_announcement_payload(&tagged),
            "a well-formed tagged announcement is classified as such"
        );
        // Arbitrary user content must NOT be classified as an announcement, so
        // it never gets routed to the shared bootstrap RID.
        assert!(
            !is_pseudonym_announcement_payload(b"hello world"),
            "ordinary app data is not an announcement"
        );
    }

    // -----------------------------------------------------------------------
    // Behavioral ingest-hardening tests — buffered site + shared validator.
    //
    // These drive a REAL `PseudonymAnnouncement` through the buffered ingest
    // entry point `deliver_plaintext_or_announcement` (which delegates the
    // full four-step validation to the shared `ingest_pseudonym_announcement`)
    // against a real `PerContextState`, and assert the registry state and
    // shared-validator outcome after each case. The direct ingest site
    // (`deliver_message_and_drain_buffered`) is exercised behaviorally in
    // `crate::context::actor` tests, where a real `ActorDeps` is available.
    // -----------------------------------------------------------------------

    use super::{
        AnnouncementOutcome, deliver_plaintext_or_announcement, ingest_pseudonym_announcement,
    };
    use crate::context::actor::state::PerContextState;

    const ALICE: &str = "did:dht:z6MkAliceIngest";
    const BOB: &str = "did:dht:z6MkBobIngest";

    fn encrypted_state() -> PerContextState {
        // Use a context-id whose hex string is what the ingest path passes as
        // `context_id`. `new_for_test_encrypted` derives the hex id internally.
        PerContextState::new_for_test_encrypted([0x11u8; 32], 1_700_000_000, DID(ALICE.to_owned()))
    }

    fn broadcast_state() -> PerContextState {
        PerContextState::new_for_test_broadcast([0x22u8; 32], 1_700_000_000, DID(BOB.to_owned()))
    }

    /// Returns the lowercase-hex context-id the test-state delivery path uses.
    fn ctx_hex(byte: u8) -> String {
        let mut s = String::with_capacity(64);
        for _ in 0..32 {
            use std::fmt::Write;
            let _ = write!(s, "{byte:02x}");
        }
        s
    }

    #[test]
    fn buffered_legitimate_announcement_is_recorded_and_updates_registry() {
        let mut state = encrypted_state();
        let ctx = ctx_hex(0x11);
        let alice_pseudonym = [0x42u8; 32];
        let bytes = announcement_bytes(ALICE, alice_pseudonym);

        let result = deliver_plaintext_or_announcement(&mut state, ALICE, &bytes, &ctx, None);
        // A recorded announcement is a buffer-only routing signal — NO durable
        // Merkle leaf is minted on receive (§9.9.3), so the typed-append channel
        // is `None`. The registry update is the observable effect.
        assert_eq!(result, None);
        // Registry now maps Alice's DID to her announced routing ID.
        let reg = state.routing.peer_registry().expect("encrypted ⇒ registry");
        assert_eq!(reg.get(&DID(ALICE.to_owned())), Some(&alice_pseudonym));
    }

    #[test]
    fn buffered_same_did_reannounce_succeeds_and_updates_registry() {
        let mut state = encrypted_state();
        let ctx = ctx_hex(0x11);
        let first = [0x42u8; 32];
        let rotated = [0x43u8; 32];

        // First announcement. Recorded announcements are buffer-only (no durable
        // Merkle leaf on receive, §9.9.3), so the typed-append channel is `None`;
        // the registry update below is the observable effect.
        assert_eq!(
            deliver_plaintext_or_announcement(
                &mut state,
                ALICE,
                &announcement_bytes(ALICE, first),
                &ctx,
                None
            ),
            None
        );
        // Same DID re-announces a rotated routing ID — legitimate key rotation.
        assert_eq!(
            deliver_plaintext_or_announcement(
                &mut state,
                ALICE,
                &announcement_bytes(ALICE, rotated),
                &ctx,
                None
            ),
            None
        );
        let reg = state.routing.peer_registry().expect("encrypted ⇒ registry");
        assert_eq!(
            reg.get(&DID(ALICE.to_owned())),
            Some(&rotated),
            "a same-DID re-announce must update (not reject) the registry"
        );
    }

    #[test]
    fn buffered_sender_did_mismatch_is_dropped_and_leaves_registry_unchanged() {
        let mut state = encrypted_state();
        let ctx = ctx_hex(0x11);
        // The announcement claims BOB but the authenticated sender is ALICE.
        let forged = announcement_bytes(BOB, [0x42u8; 32]);

        let result = deliver_plaintext_or_announcement(&mut state, ALICE, &forged, &ctx, None);
        assert_eq!(result, None, "a forged-DID announcement must be dropped");
        let reg = state.routing.peer_registry().expect("encrypted ⇒ registry");
        assert!(
            reg.is_empty(),
            "a rejected announcement must not touch the registry"
        );
    }

    #[test]
    fn buffered_reserved_values_are_dropped() {
        let ctx = ctx_hex(0x11);
        for reserved in [
            [0u8; 32],
            scp_protocol::context::context_routing_id(&ctx),
            scp_protocol::context::broadcast_routing_id(&ctx),
        ] {
            let mut state = encrypted_state();
            let bytes = announcement_bytes(ALICE, reserved);
            assert_eq!(
                deliver_plaintext_or_announcement(&mut state, ALICE, &bytes, &ctx, None),
                None,
                "a reserved pseudonym value must be dropped"
            );
            assert!(
                state
                    .routing
                    .peer_registry()
                    .expect("encrypted ⇒ registry")
                    .is_empty(),
                "a reserved-value announcement must not touch the registry"
            );
        }
    }

    #[test]
    fn buffered_cross_did_collision_is_dropped() {
        let mut state = encrypted_state();
        let ctx = ctx_hex(0x11);
        let shared_rid = [0x55u8; 32];

        // Alice legitimately claims `shared_rid` first. Recorded ⇒ buffer-only
        // (no durable Merkle leaf on receive, §9.9.3) ⇒ `None`; the registry
        // assertions below distinguish Recorded (inserted) from Rejected.
        assert_eq!(
            deliver_plaintext_or_announcement(
                &mut state,
                ALICE,
                &announcement_bytes(ALICE, shared_rid),
                &ctx,
                None
            ),
            None
        );
        // Bob tries to claim Alice's already-registered routing ID → collision.
        assert_eq!(
            deliver_plaintext_or_announcement(
                &mut state,
                BOB,
                &announcement_bytes(BOB, shared_rid),
                &ctx,
                None
            ),
            None,
            "a cross-DID routing-ID collision must be dropped"
        );
        let reg = state.routing.peer_registry().expect("encrypted ⇒ registry");
        assert_eq!(reg.get(&DID(ALICE.to_owned())), Some(&shared_rid));
        assert!(
            !reg.contains_key(&DID(BOB.to_owned())),
            "the colliding announcer must not be inserted"
        );
    }

    #[test]
    fn buffered_announcement_on_broadcast_context_is_dropped() {
        let mut state = broadcast_state();
        let ctx = ctx_hex(0x22);
        let bytes = announcement_bytes(BOB, [0x42u8; 32]);
        assert_eq!(
            deliver_plaintext_or_announcement(&mut state, BOB, &bytes, &ctx, None),
            None,
            "an announcement on a broadcast context (no peer registry) must be dropped"
        );
        assert!(
            state.routing.peer_registry().is_none(),
            "broadcast contexts carry no peer registry"
        );
    }

    #[test]
    fn buffered_non_announcement_is_delivered_as_normal_message() {
        let mut state = encrypted_state();
        let ctx = ctx_hex(0x11);
        let buffered_before = state.receive_buffer.event_log_entries().len();
        let result =
            deliver_plaintext_or_announcement(&mut state, ALICE, b"hello world", &ctx, None);
        // A non-announcement application message is pushed to the in-memory
        // receive buffer but NOT minted as a durable Merkle leaf (a
        // receiver-minted MessageReceived leaf is not sender-authenticated and
        // would let honest receivers diverge their roots, §9.9.3), so the
        // function returns None.
        assert_eq!(result, None);
        assert_eq!(
            state.receive_buffer.event_log_entries().len(),
            buffered_before + 1,
            "the received message must still be buffered for SDK observation"
        );
    }

    /// The shared validator returns the EXACT outcome each call site maps:
    /// buffered → `None` on `Rejected`, direct → `Err(PermissionDenied)`. This
    /// proves the two sites cannot diverge — they share one boundary.
    #[test]
    fn shared_validator_outcomes_match_each_sites_contract() {
        let ctx = ctx_hex(0x11);

        // NotAnnouncement: ordinary app data.
        let mut s = encrypted_state();
        assert!(matches!(
            ingest_pseudonym_announcement(&mut s, ALICE, b"plain", &ctx, None),
            AnnouncementOutcome::NotAnnouncement
        ));

        // Recorded: legitimate announcement.
        let mut s = encrypted_state();
        assert!(matches!(
            ingest_pseudonym_announcement(
                &mut s,
                ALICE,
                &announcement_bytes(ALICE, [9u8; 32]),
                &ctx,
                None
            ),
            AnnouncementOutcome::Recorded
        ));

        // Rejected: forged DID — carries a stable reason the direct site maps
        // verbatim into `PermissionDenied`.
        let mut s = encrypted_state();
        assert!(matches!(
            ingest_pseudonym_announcement(
                &mut s,
                ALICE,
                &announcement_bytes(BOB, [9u8; 32]),
                &ctx,
                None
            ),
            AnnouncementOutcome::Rejected(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Regression: buffered-drain post-delivery governance MUST run for
    // application messages even though they produce no Merkle append.
    //
    // The Merkle-append suppression for received application messages (§9.9.3 —
    // a receiver-minted `MessageReceived` leaf is not sender-authenticated, so
    // appending it would let honest receivers diverge their roots) made
    // `deliver_plaintext_or_announcement` return `None` for app data. The four
    // buffered-drain call sites previously gated ALL of
    // `run_buffered_post_delivery` on that `Some`, which silently dropped
    // velocity tracking, consequence evaluation/enforcement, and the
    // `checkpoint_events_since` increment for every buffered application
    // message — only announcements (still `Some`) stayed covered. The in-order
    // path always ran these unconditionally, so the buffered path had drifted.
    //
    // This test drives the post-delivery helper with `event_name == None` (the
    // application-message case) and asserts all three governance side effects
    // still fire. It FAILS against the gated implementation (the helper was
    // never called) and PASSES once the append is decoupled from governance.
    // -----------------------------------------------------------------------

    use crate::context::actor::state::PerContextState as RegressionState;
    use scp_primitives::TestClock;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

    /// Event-log provider that flags which `EventType`s were appended so the
    /// test can prove (a) consequence evaluation/enforcement DID append a
    /// `ConsequenceTriggered` event and (b) the application message itself
    /// appended NO `MessageSent` Merkle leaf for a `None` event type. Uses
    /// atomics only (no `Mutex`) per ADR-049's runtime-state model.
    #[derive(Default)]
    struct RecordingEventLog {
        saw_consequence_triggered: AtomicBool,
        saw_message_sent: AtomicBool,
    }

    impl crate::context::builder::ContextEventLogProvider for RecordingEventLog {
        fn init_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }

        fn append_event(
            &self,
            _id: &[u8; 32],
            event: scp_event_log::EventType,
            _actor: &str,
            _payload: scp_event_log::EventPayload,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            match event {
                scp_event_log::EventType::ConsequenceTriggered => {
                    self.saw_consequence_triggered
                        .store(true, AtomicOrdering::SeqCst);
                }
                scp_event_log::EventType::MessageSent => {
                    self.saw_message_sent.store(true, AtomicOrdering::SeqCst);
                }
                _ => {}
            }
            Ok(())
        }

        fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    #[test]
    fn buffered_application_message_runs_velocity_consequence_and_checkpoint() {
        use crate::context::messaging_helpers::{
            deliver_plaintext_or_announcement, run_buffered_post_delivery,
        };
        use scp_protocol::trust::consequence::{
            ConsequenceAction, ConsequenceRule, ConsequenceTrigger, EnforcementSeverity,
        };

        let ctx = ctx_hex(0x11);
        let ctx_bytes = scp_protocol::context::context_id_bytes(&ctx);
        let mut state: RegressionState = encrypted_state();

        // Install a MessageVelocity rule that triggers on the FIRST message from
        // a sender. Received application messages are projected to
        // `EventType::MessageSent` for consequence purposes
        // (`event_log_entries_for_consequences`), so one buffered app message is
        // enough to trip threshold 1. The triggered consequence carries non-empty
        // evidence, so `ConsequenceTriggered` is emitted even though the sender is
        // not in the test fixture's (empty) membership set.
        state.governance.consequence_rules.push(ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess),
            threshold: 1,
            window: std::time::Duration::from_hours(1),
        });

        let clock = TestClock::new(1_700_000_100);
        let event_log = RecordingEventLog::default();

        let checkpoint_before = state.checkpoint_events_since;

        // Deliver an ordinary application message via the buffered ingest entry
        // point. It is pushed to the receive buffer but returns `None` (no
        // sender-authenticated Merkle leaf — §9.9.3).
        let event_name =
            deliver_plaintext_or_announcement(&mut state, ALICE, b"hello world", &ctx, None);
        assert_eq!(
            event_name, None,
            "a received application message must not mint a durable Merkle leaf"
        );

        // Post-delivery governance MUST run unconditionally, mirroring the
        // in-order path — this is exactly the call shape the four buffered-drain
        // sites now use.
        run_buffered_post_delivery(
            &mut state, &ctx, &ctx_bytes, ALICE, event_name, &clock, &event_log, None,
        );

        // (a) Velocity was recorded for the sender.
        let velocity = state.governance.velocity_tracker.snapshot_entries();
        assert!(
            velocity.get(ALICE).is_some_and(|ts| !ts.is_empty()),
            "buffered application message must record sender velocity (was skipped by the gated bug)"
        );

        // (b) Consequence evaluation + enforcement ran: a `ConsequenceTriggered`
        // event was appended to the durable log. The `None` event type means the
        // application message itself appended NO message leaf (§9.9.3 — there is
        // no `MessageReceived` variant in the closed event taxonomy precisely
        // because received app messages are never durably logged); the only
        // appends come from consequence enforcement.
        assert!(
            event_log
                .saw_consequence_triggered
                .load(AtomicOrdering::SeqCst),
            "buffered application message must run consequence evaluation/enforcement \
             (gated bug skipped it)"
        );
        assert!(
            !event_log.saw_message_sent.load(AtomicOrdering::SeqCst),
            "a received application message must NOT append a MessageSent Merkle leaf (§9.9.3)"
        );

        // (c) The checkpoint counter advanced for the delivered application
        // message. `run_buffered_post_delivery` increments it once for the
        // message itself; consequence enforcement increments it again per
        // emitted `Consequence*` event, so the total is strictly greater than
        // the pre-delivery value. The gated bug left it UNCHANGED.
        assert!(
            state.checkpoint_events_since > checkpoint_before,
            "buffered application message must advance checkpoint_events_since (was skipped by the gated bug): \
             before={checkpoint_before}, after={}",
            state.checkpoint_events_since
        );
    }

    // -----------------------------------------------------------------------
    // STRONGER regression: drive a buffered APPLICATION message END-TO-END
    // through a REAL buffered-drain call site so a re-introduced
    // `if let Some(event_name) { run_buffered_post_delivery(...) }` gate is
    // caught.
    //
    // The helper-contract test above calls `run_buffered_post_delivery`
    // DIRECTLY, so it proves the helper does the right thing GIVEN it is
    // called — but it cannot observe the four call sites that decide WHETHER
    // to call it. The actual bug lived at those call sites (the
    // `deliver_plaintext_or_announcement` result was gated through
    // `if let Some(...)`, which is `None` for application data, so governance
    // was skipped). This test exercises `validate_and_drain_timeouts` — one of
    // the four real drain paths — with a buffered-ahead application message
    // that times out, forcing the call site to run
    // `deliver_plaintext_or_announcement` (→ `None`) followed by
    // `run_buffered_post_delivery`. It asserts the governance side effects fire
    // (velocity recorded + `ConsequenceTriggered` appended + checkpoint
    // advanced) WITHOUT a `MessageSent` Merkle leaf. Re-adding an `if let Some`
    // gate around the call site makes this test FAIL (governance is skipped for
    // the `None`-typed application message), which the helper-contract test
    // would not catch.
    // -----------------------------------------------------------------------

    /// Event-log provider that records appended `EventType`s through shared
    /// `Arc<AtomicBool>` handles, so the test can read them AFTER the provider
    /// has been moved into the supervisor / `ActorDeps`. Atomics only (no
    /// `Mutex`) per ADR-049's runtime-state model.
    struct DrainRecordingEventLog {
        consequence_triggered: std::sync::Arc<std::sync::atomic::AtomicBool>,
        message_sent: std::sync::Arc<std::sync::atomic::AtomicBool>,
        /// `EventType` enumerates 75 variants; `PseudonymAnnounced` was REMOVED
        /// (it is a `ContextEvent`-only routing signal, not a durable event). A
        /// recorder cannot match a non-existent variant, so a received
        /// announcement is proven buffer-only by the ABSENCE of any append at
        /// all (`any_append == false`) after the announcement-drain path.
        any_append: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl crate::context::builder::ContextEventLogProvider for DrainRecordingEventLog {
        fn init_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }

        fn append_event(
            &self,
            _id: &[u8; 32],
            event: scp_event_log::EventType,
            _actor: &str,
            _payload: scp_event_log::EventPayload,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            self.any_append
                .store(true, std::sync::atomic::Ordering::SeqCst);
            match event {
                scp_event_log::EventType::ConsequenceTriggered => {
                    self.consequence_triggered
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
                scp_event_log::EventType::MessageSent => {
                    self.message_sent
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
                _ => {}
            }
            Ok(())
        }

        fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    /// Minimal application-message `InnerEnvelope` for the drain test. The
    /// drain path reads only `sequence`/`timestamp`/`context_id`/`sender_did`;
    /// the body is the separate `plaintext` argument.
    fn drain_test_inner(ctx: &str, sequence: u64) -> scp_protocol::envelope::inner::InnerEnvelope {
        scp_protocol::envelope::inner::InnerEnvelope {
            version: scp_protocol::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
            context_id: ctx.to_owned(),
            sender_did: ALICE.to_owned(),
            epoch: 0,
            generation: 0,
            sequence,
            timestamp: 1_700_000_000,
            message_type: scp_protocol::envelope::inner::MessageType::Content,
            payload_hash: [0u8; 32],
            payload: Vec::new(),
            provenance: None,
            provenance_hash: [0u8; 32],
            signing_key_id: scp_protocol::identity::SigningKeyId::Active,
            signature: [0u8; 64],
            extensions: std::collections::HashMap::new(),
        }
    }

    /// Assemble a supervisor-backed `ActorDeps` carrying `event_log` and a
    /// `TestClock`. Extracted so the drain test stays under `too_many_lines`.
    async fn build_drain_test_deps(
        event_log: Box<dyn crate::context::builder::ContextEventLogProvider>,
    ) -> crate::context::actor::deps::ActorDeps {
        use crate::context::supervisor::supervisor::Supervisor;
        use scp_platform::testing::InMemoryStorage;
        use std::sync::Arc;

        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            ALICE.to_owned(),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let key_resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_| None);
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        let clock: Arc<dyn scp_primitives::Clock> =
            Arc::new(scp_primitives::TestClock::new(1_700_000_000));
        let supervisor = Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            None,
            None,
            None,
            Some(clock),
            mls_storage,
        );
        supervisor
            .build_actor_deps(&DID(ALICE.to_owned()))
            .await
            .expect("build_actor_deps")
    }

    #[tokio::test]
    async fn buffered_drain_call_site_runs_governance_for_application_message() {
        use crate::context::messaging_helpers::validate_and_drain_timeouts;
        use scp_protocol::context::roles::Capability;
        use scp_protocol::envelope::validation::{BufferedMessage, DEFAULT_GAP_TIMEOUT_MS};
        use scp_protocol::trust::consequence::{
            ConsequenceAction, ConsequenceRule, ConsequenceTrigger, EnforcementSeverity,
        };
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

        let ctx = ctx_hex(0x11);
        let mut state: PerContextState = encrypted_state();

        // ALICE must be a writable member: the drain loop re-checks membership +
        // `MessagesWrite` before delivering each buffered message.
        state
            .membership
            .add_member(DID(ALICE.to_owned()), "member".to_owned(), Vec::new());
        state.members.insert(DID(ALICE.to_owned()));
        state.role_state.members.insert(ALICE.to_owned());
        let mut caps = std::collections::HashSet::new();
        caps.insert(Capability::MessagesWrite);
        state
            .role_state
            .member_capabilities
            .insert(ALICE.to_owned(), caps);

        // A MessageVelocity rule that trips on the first message. Received
        // application messages project to `EventType::MessageSent` for
        // consequence purposes, so one buffered app message trips threshold 1
        // and emits `ConsequenceTriggered` (non-empty evidence).
        state.governance.consequence_rules.push(ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess),
            threshold: 1,
            window: std::time::Duration::from_hours(1),
        });

        // Pre-buffer an out-of-order APPLICATION message (sequence 2, expected
        // 1) with `received_at = 0` so it is past the gap timeout once we pass a
        // large `now_ms`. This is a plain application payload (not a pseudonym
        // announcement), so on drain `deliver_plaintext_or_announcement` returns
        // `None` — exactly the case the gated bug dropped.
        let buffered = state.reorder_buffer.buffer(BufferedMessage {
            inner: drain_test_inner(&ctx, 2),
            sender_did: ALICE.to_owned(),
            plaintext: b"buffered application payload".to_vec(),
            received_at: 0,
        });
        assert!(
            buffered.is_none(),
            "single buffered message must not overflow the reorder buffer"
        );

        // Shared recording handles survive the move into the supervisor.
        let saw_consequence_triggered = Arc::new(AtomicBool::new(false));
        let saw_message_sent = Arc::new(AtomicBool::new(false));
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(DrainRecordingEventLog {
                consequence_triggered: Arc::clone(&saw_consequence_triggered),
                message_sent: Arc::clone(&saw_message_sent),
                any_append: Arc::new(AtomicBool::new(false)),
            });
        let deps = build_drain_test_deps(event_log).await;

        let checkpoint_before = state.checkpoint_events_since;

        // Drive the REAL drain call site: the incoming in-order message (seq 1)
        // is validated, and `now_ms` is past the gap timeout, so the buffered
        // seq-2 application message force-drains through
        // `validate_and_drain_timeouts`' loop — which calls
        // `deliver_plaintext_or_announcement` (→ `None`) then
        // `run_buffered_post_delivery`. A re-added `if let Some` gate here would
        // skip governance for the `None`-typed application message.
        let incoming = drain_test_inner(&ctx, 1);
        let now_ms = 1_700_000_000 + DEFAULT_GAP_TIMEOUT_MS + 10;
        validate_and_drain_timeouts(&mut state, &deps, &ctx, &incoming, now_ms)
            .expect("validate_and_drain_timeouts");

        // (a) Velocity recorded for the buffered sender via the drain path.
        let velocity = state.governance.velocity_tracker.snapshot_entries();
        assert!(
            velocity.get(ALICE).is_some_and(|ts| !ts.is_empty()),
            "buffered-drain call site must record sender velocity (a re-added `if let Some` gate skips it)"
        );

        // (b) Consequence evaluation/enforcement ran (a `ConsequenceTriggered`
        // event was appended) and the application message itself appended NO
        // `MessageSent` Merkle leaf (§9.9.3 — received app messages are never
        // durably logged).
        assert!(
            saw_consequence_triggered.load(AtomicOrdering::SeqCst),
            "buffered-drain call site must run consequence evaluation/enforcement (a re-added `if let Some` gate skips it)"
        );
        assert!(
            !saw_message_sent.load(AtomicOrdering::SeqCst),
            "a received application message must NOT append a MessageSent Merkle leaf (§9.9.3)"
        );

        // (c) The checkpoint counter advanced for the drained application
        // message. The gated bug left it unchanged.
        assert!(
            state.checkpoint_events_since > checkpoint_before,
            "buffered-drain call site must advance checkpoint_events_since (a re-added `if let Some` gate skips it): \
             before={checkpoint_before}, after={}",
            state.checkpoint_events_since
        );
    }

    // -----------------------------------------------------------------------
    // Regression: a RECEIVED pseudonym announcement must NOT mint a durable
    // Merkle leaf.
    //
    // PseudonymAnnounced is a §9.10.4 routing-bootstrap `ContextEvent` signal,
    // not a durable event (it was removed from the closed `EventType` taxonomy).
    // A received announcement updates the in-memory peer registry and emits a
    // `ContextEvent::PseudonymAnnounced` buffer notification, but a per-receiver,
    // per-arrival-order Merkle append cannot converge across honest members and
    // would false-positive §9.9.3 equivocation detection. This test drives a
    // legitimate in-order announcement through the REAL direct delivery path
    // (`deliver_message_and_drain_buffered`) and asserts (a) the registry was
    // updated (the announcement WAS processed) and (b) NO event was appended to
    // the durable log at all. A re-introduced receive-path append would set
    // `saw_any_append` and fail this test.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn received_announcement_updates_registry_without_durable_append() {
        use crate::context::messaging_helpers::deliver_message_and_drain_buffered;
        use scp_protocol::context::roles::Capability;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

        let ctx = ctx_hex(0x11);
        let ctx_bytes = scp_protocol::context::context_id_bytes(&ctx);
        let mut state: PerContextState = encrypted_state();

        // The direct delivery path requires an Active context handle.
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .expect("transition to Active");

        // ALICE must be a writable member: the direct path checks membership +
        // `MessagesWrite` before delivering.
        state
            .membership
            .add_member(DID(ALICE.to_owned()), "member".to_owned(), Vec::new());
        state.members.insert(DID(ALICE.to_owned()));
        state.role_state.members.insert(ALICE.to_owned());
        let mut caps = std::collections::HashSet::new();
        caps.insert(Capability::MessagesWrite);
        state
            .role_state
            .member_capabilities
            .insert(ALICE.to_owned(), caps);

        let saw_any_append = Arc::new(AtomicBool::new(false));
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(DrainRecordingEventLog {
                consequence_triggered: Arc::new(AtomicBool::new(false)),
                message_sent: Arc::new(AtomicBool::new(false)),
                any_append: Arc::clone(&saw_any_append),
            });
        let deps = build_drain_test_deps(event_log).await;

        // A legitimate in-order pseudonym announcement (ALICE announces her own
        // routing ID). The drain path reads sequence/timestamp/context/sender
        // from the inner envelope; the announcement payload is the `plaintext`.
        let alice_pseudonym = [0x42u8; 32];
        let announcement = crate::context::state::PseudonymAnnouncement {
            tag: crate::context::state::PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
            member_did: ALICE.to_owned(),
            pseudonym: alice_pseudonym,
        };
        let plaintext = rmp_serde::to_vec_named(&announcement).expect("serialize announcement");
        let inner = drain_test_inner(&ctx, 1);

        let consumed = deliver_message_and_drain_buffered(
            &mut state, &deps, &ctx, &ctx_bytes, ALICE, &inner, &plaintext, false,
        )
        .expect("deliver_message_and_drain_buffered");

        // The announcement WAS recognized + processed (consumed as an internal
        // protocol message) and inserted into the in-memory peer registry.
        assert!(
            consumed,
            "a tagged pseudonym announcement must be consumed as an internal protocol message"
        );
        let reg = state.routing.peer_registry().expect("encrypted ⇒ registry");
        assert_eq!(
            reg.get(&DID(ALICE.to_owned())),
            Some(&alice_pseudonym),
            "a processed announcement must update the in-memory peer registry (its entire function)"
        );

        // But NO durable Merkle leaf was appended on the receive path: a received
        // announcement is buffer-only (§9.9.3 non-convergence). There are no
        // consequence rules installed, so the ONLY append a regression could add
        // is the removed receive-path PseudonymAnnounced leaf.
        assert!(
            !saw_any_append.load(AtomicOrdering::SeqCst),
            "a received pseudonym announcement must NOT mint any durable Merkle leaf (§9.9.3)"
        );
    }

    // -----------------------------------------------------------------------
    // Consistency-checkpoint wire message (§9.9.3, §23.7)
    // -----------------------------------------------------------------------

    use crate::context::state::{CHECKPOINT_PAYLOAD_TAG, CheckpointMessage};

    fn sample_checkpoint(sender: &str) -> scp_event_log::checkpoint::ConsistencyCheckpoint {
        scp_event_log::checkpoint::ConsistencyCheckpoint {
            context_id: "ctx-1".to_owned(),
            sender_did: DID(sender.to_owned()),
            event_count: 42,
            merkle_root: [7u8; 32],
            epoch: Some(3),
            timestamp: 1_700_000_000,
            signature: vec![0xAB; 64],
        }
    }

    /// The on-the-wire checkpoint message round-trips through `MessagePack`
    /// (the format `send_checkpoint` produces and `deliver_checkpoint_message`
    /// consumes).
    #[test]
    fn checkpoint_message_roundtrips_over_messagepack() {
        let msg = CheckpointMessage {
            tag: CHECKPOINT_PAYLOAD_TAG.to_owned(),
            checkpoint: sample_checkpoint(ALICE),
        };
        let bytes = rmp_serde::to_vec_named(&msg).expect("serialize checkpoint message");
        let decoded: CheckpointMessage =
            rmp_serde::from_slice(&bytes).expect("deserialize checkpoint message");
        assert_eq!(decoded.tag, CHECKPOINT_PAYLOAD_TAG);
        assert_eq!(decoded.checkpoint, msg.checkpoint);
    }

    /// The checkpoint tag is `\0`-prefixed so ordinary UTF-8 application
    /// content can never be mistaken for a checkpoint message, mirroring the
    /// pseudonym-announcement tag invariant.
    #[test]
    fn checkpoint_tag_is_null_prefixed() {
        assert!(
            CHECKPOINT_PAYLOAD_TAG.starts_with('\0'),
            "checkpoint tag must be null-prefixed to avoid UTF-8 content collision"
        );
        assert_ne!(
            CHECKPOINT_PAYLOAD_TAG,
            crate::context::state::PSEUDONYM_ANNOUNCEMENT_TAG,
            "checkpoint and announcement tags must be distinct"
        );
    }
}
