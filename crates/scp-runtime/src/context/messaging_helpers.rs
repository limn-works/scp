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
//! borrowed. No `relock_context` / `ContextGeneration` confused-deputy
//! dance is needed because each actor is its own generation.
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
    self, PSEUDONYM_ANNOUNCEMENT_TAG, PseudonymAnnouncement, emit_event_into,
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
/// Uses [`scp_protocol::context::context_routing_id`] for the outer
/// envelope's `routing_id` per ADR-002 domain-separation.
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
        message_type: MessageType::Content,
        payload: &wrapped_bytes,
        provenance,
        signing_key_id: SigningKeyId::Active,
    };

    let inner = crate::envelope::inner::sign::create_inner_envelope_raw(&params, signing_key)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    let routing_id = scp_protocol::context::context_routing_id(context_id);
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
/// pseudonym announcement first. Returns the event-log event name for the
/// delivered message, or `None` when silently dropped.
pub fn deliver_plaintext_or_announcement(
    state: &mut PerContextState,
    sender_did: &str,
    plaintext: &[u8],
    context_id: &str,
    event_tx: Option<&ContextEventSender>,
) -> Option<&'static str> {
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
            return None;
        }
        let did = DID(announcement.member_did.clone());
        state
            .pseudonym_registry
            .insert(did.clone(), announcement.pseudonym);
        let event = ContextEvent::PseudonymAnnounced {
            member_did: did,
            pseudonym: announcement.pseudonym,
        };
        emit_event_into(&mut state.receive_buffer, event, context_id, event_tx);
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
    emit_event_into(&mut state.receive_buffer, event, context_id, event_tx);
    Some("MessageReceived")
}

// ---------------------------------------------------------------------------
// 6. run_buffered_post_delivery
// ---------------------------------------------------------------------------

/// Runs post-delivery governance logic for a single buffered/drained
/// message. Bug fix (#1534): velocity, event-log append, consequence
/// evaluation, and checkpoint increment apply to buffered messages too.
#[allow(clippy::too_many_arguments)]
pub fn run_buffered_post_delivery(
    state: &mut PerContextState,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    sender_did: &str,
    event_name: &str,
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

    if let Err(e) = event_log.append_context_event(context_id_bytes, event_name, sender_did) {
        tracing::warn!(
            context_id,
            sender_did,
            event_name,
            "failed to append buffered event to event log: {e}"
        );
    }

    let consequence_rules: Vec<ConsequenceRule> = state.governance.consequence_rules.clone();
    if !consequence_rules.is_empty() {
        let events = crate::context::governance_logic::event_log_entries_for_consequences_split(
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
        crate::context::governance_logic::enforce_triggered_consequences_split(
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
                crate::context::economy_logic::rollback_economy_ticket_inline_split(
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
                    crate::context::economy_logic::rollback_economy_ticket_inline_split(
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
                crate::context::economy_logic::rollback_economy_ticket_inline_split(
                    &mut state.governance,
                    ticket,
                );
                return Err(ContextError::MemberNotFound(format!(
                    "cannot assign sequence: {sender_did} is not a member"
                )));
            };
            // §9.10.4: collect pseudonym routing IDs for fan-out.
            let mut routing_ids: Vec<[u8; 32]> =
                state.pseudonym_registry.values().copied().collect();
            let shared_rid = scp_protocol::context::context_routing_id(&context_id);
            routing_ids.push(shared_rid);
            (
                None,
                state.access.access_key_store.get_all(&context_id),
                seq,
                false,
                routing_ids,
            )
        };

    // Payment flow: authorize (hold) before action.
    let auth = match authorize_send_payment(state, deps, &context_id, sender_did).await {
        Ok(auth) => auth,
        Err(e) => {
            crate::context::economy_logic::rollback_economy_ticket_inline_split(
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
    );
    if let Err(e) = phase2_result {
        // Void escrow + roll back ticket on send failure.
        if let Some(a) = auth {
            crate::context::economy_helpers::void_paid_action(state, deps, a, &context_id).await;
        }
        crate::context::economy_logic::rollback_economy_ticket_inline_split(
            &mut state.governance,
            ticket,
        );
        if !is_broadcast {
            state.membership.rollback_sequence_number(sender_did);
        }
        return Err(e);
    }

    // Phase 3: capture escrow + finalize.
    let deducted_cost = crate::context::economy_logic::commit_economy_ticket(ticket);
    capture_send_payment(state, deps, auth, sender_did, &context_id, deducted_cost).await;

    finalize_send(
        state,
        deps,
        &context_id,
        &context_id_bytes,
        sender_did,
        sequence,
        payload,
        signing_key,
    )
}

// ---------------------------------------------------------------------------
// 8. deliver_incoming (top-level, actor-shape)
// ---------------------------------------------------------------------------

/// Delivers an incoming encrypted message from the relay to a context
/// (actor-shape). Returns the decrypted plaintext + sender DID for
/// application messages, `None` for management messages or buffered
/// out-of-order arrivals.
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
) -> Result<Option<(Vec<u8>, String)>, ContextError> {
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
        return Ok(None);
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
                Ok(None)
            } else {
                Ok(Some((plaintext, sender_did)))
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
            Ok(None)
        }
    }
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
        )?;
        crate::metrics::record_encrypt_duration(encrypt_start.elapsed());
        result
    };
    // §9.10.4: fan-out — seal once, send to all routing IDs.
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
    let payload = serde_json::json!({
        "action": action,
        "error": error_msg,
        "cost": cost.map(scp_protocol::economy::types::Amount::value),
    });
    if let Err(log_err) = deps.event_log.append_context_event_with_payload(
        &context_id_bytes,
        "PaymentCaptureFailed",
        actor_did.as_ref(),
        Some(&payload),
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

/// Pushes a `MessageSent` event, appends to the event log, runs
/// consequence enforcement, and persists. Actor-shape: no relock
/// dance — `state` is borrowed throughout.
///
/// Sync — no await points in the actor body. The caller (`send_message`)
/// stays `async` because it threads through escrow / transport awaits
/// before `finalize_send`.
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
) -> Result<(), ContextError> {
    // M12: append event log BEFORE consequence evaluation.
    deps.event_log
        .append_context_event(context_id_bytes, "MessageSent", sender_did.as_ref())?;

    // Phase 3 reacquire-and-mutate is unnecessary in the actor model;
    // the actor owns state for the duration of the command. We DO
    // re-check the lifecycle state — a TTL expiry could land between
    // Phase 1 and finalize within the same command if the actor's TTL
    // arm fires (Phase 2A.9 wires this). For Phase 2A.7 this matches
    // the legacy contract: rollback the sequence number and exit.
    if state::require_active(&state.handle).is_err() {
        state.membership.rollback_sequence_number(sender_did);
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
    let send_events = crate::context::governance_logic::event_log_entries_for_consequences_split(
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
        crate::context::governance_logic::enforce_triggered_consequences_split(
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
    let send_merkle = deps
        .event_log
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
        state
            .governance
            .participation_cache
            .insert(sender_did.to_string(), record);
    }

    // Checkpoint tracking (§9.9.3).
    state.checkpoint_events_since += 1;
    if let Some(sk) = signing_key {
        let broadcast_context_is_none = state.broadcast_context.is_none();
        let mls_epoch = state.epoch.mls_epoch;
        crate::context::queries_helpers::create_checkpoint_if_due_split(
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
    }

    persist_state_best_effort(state, deps, context_id);
    Ok(())
}

/// Best-effort persist of the current actor state. Mirrors the legacy
/// Phase 3 snapshot persistence path, but reads from actor-owned state.
pub fn persist_state_best_effort(state: &PerContextState, deps: &ActorDeps, context_id: &str) {
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
    if let Err(e) = deps.persistence.persist_context(context_id, &snapshot) {
        crate::metrics::record_persistence_failure();
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to persist context snapshot"
        );
    }
}

#[allow(clippy::too_many_lines)]
pub fn build_snapshot_from_state(
    state: &PerContextState,
) -> crate::context::state::ContextSnapshot {
    use crate::context::state::VelocityTrackerSnapshot;
    use scp_protocol::context::ContextState;

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
        pending_commits: state.pending_commits.clone(),
        commit_fault: state.commit_fault.clone(),
        checkpoint_events_since: state.checkpoint_events_since,
        checkpoint_last_time_secs: state.checkpoint_last_time_secs,
        generation: state.generation,
        local_pseudonym: state.local_pseudonym,
        pseudonym_registry: state
            .pseudonym_registry
            .iter()
            .map(|(did, p)| (did.to_string(), *p))
            .collect(),
    }
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
            if let Some(event_name) = deliver_plaintext_or_announcement(
                state,
                &msg.sender_did,
                &msg.plaintext,
                context_id,
                deps.event_tx.as_ref(),
            ) {
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
            if let Some(event_name) = deliver_plaintext_or_announcement(
                state,
                &msg.sender_did,
                &msg.plaintext,
                context_id,
                deps.event_tx.as_ref(),
            ) {
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

    // §9.10.4: pseudonym announcement?
    if let Ok(announcement) = rmp_serde::from_slice::<PseudonymAnnouncement>(plaintext)
        && announcement.tag == PSEUDONYM_ANNOUNCEMENT_TAG
    {
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
        state
            .pseudonym_registry
            .insert(announced_did.clone(), announcement.pseudonym);
        let announce_event = ContextEvent::PseudonymAnnounced {
            member_did: announced_did,
            pseudonym: announcement.pseudonym,
        };
        emit_event_into(
            &mut state.receive_buffer,
            announce_event,
            context_id,
            deps.event_tx.as_ref(),
        );
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
            if let Some(event_name) = deliver_plaintext_or_announcement(
                state,
                &msg.sender_did,
                &msg.plaintext,
                context_id,
                deps.event_tx.as_ref(),
            ) {
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
        }

        let now = deps.clock.now_secs();
        if !skip_velocity {
            state
                .governance
                .velocity_tracker
                .record_message(&DID(sender_did.to_owned()), now);
        }
        if let Err(e) =
            deps.event_log
                .append_context_event(context_id_bytes, "PseudonymAnnounced", sender_did)
        {
            tracing::warn!(
                context_id,
                sender_did,
                "failed to append PseudonymAnnounced to event log: {e}"
            );
        }
        let consequence_rules: Vec<ConsequenceRule> = state.governance.consequence_rules.clone();
        if !consequence_rules.is_empty() {
            let recv_events =
                crate::context::governance_logic::event_log_entries_for_consequences_split(
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
            crate::context::governance_logic::enforce_triggered_consequences_split(
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
        if let Some(event_name) = deliver_plaintext_or_announcement(
            state,
            &msg.sender_did,
            &msg.plaintext,
            context_id,
            deps.event_tx.as_ref(),
        ) {
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
    }

    // H5: append durable event log entry BEFORE consequence eval.
    if let Err(e) =
        deps.event_log
            .append_context_event(context_id_bytes, "MessageReceived", sender_did)
    {
        tracing::warn!(
            context_id,
            sender_did,
            "failed to append MessageReceived to event log on receive path: {e}"
        );
    }

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
        let recv_events =
            crate::context::governance_logic::event_log_entries_for_consequences_split(
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
        crate::context::governance_logic::enforce_triggered_consequences_split(
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
    let Some(pseudonym) = state.local_pseudonym else {
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
            "failed to send pseudonym announcement — other members will use shared routing"
        );
    }
}
