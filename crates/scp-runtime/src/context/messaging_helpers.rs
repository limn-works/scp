//! Messaging helpers — actor-shape signatures
//! (ADR-049 Phase 2A.7, `messaging` domain migration).
//!
//! # Purpose
//!
//! This module hosts messaging-domain helpers that operate on actor-owned
//! [`PerContextState`](crate::context::actor::state::PerContextState) and
//! capability-reduced [`ActorDeps`](crate::context::actor::deps::ActorDeps).
//! The pre-migration `&Supervisor` lock-and-call bodies have been removed
//! (Phase 2A finalization); this module is the sole home for these helpers.
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
//! 1. [`build_inner_wire`] (pure: access-key wrap + inner-envelope
//!    sign+pad) feeding [`build_encrypted_envelope_actor`] — the
//!    ADR-049 PR-7 actor seal (sender-key + MLS + outer-envelope)
//!    against an actor-owned `ContextCryptoState`.
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
//! 10. [`authorize_send_payment_prepare`] — Phase 1.5 escrow auth.
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

use scp_clock::Clock;
use scp_did::{DID, SigningKeyId};
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::pseudonym::{
    self, PSEUDONYM_ANNOUNCEMENT_TAG, PseudonymAnnouncement, PseudonymAnnouncementDecision,
    classify_pseudonym_announcement, is_pseudonym_announcement_payload,
};
use scp_protocol::context::roles::Capability;
use scp_protocol::crypto::access_keys::wrapping::Recipient;
use scp_protocol::crypto::access_keys::{AccessKey, WrappedContent};
use scp_protocol::crypto::sender_keys::broadcast::BroadcastEnvelope;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::envelope::inner::{InnerEnvelope, InnerEnvelopeParams, MessageType};
use scp_protocol::envelope::validation::SequenceCheck;
use scp_protocol::provenance::attach::SourceContextInfo;
use scp_protocol::trust::consequence::{ConsequenceRule, evaluate_consequence_rules};

use crate::context::ContextHandle;
use crate::context::actor::class_s::{BroadcastContextClassCMut, ClassCMut};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::governance_helpers;
use crate::context::state::{self, CHECKPOINT_PAYLOAD_TAG, CheckpointMessage, emit_event_into};
use crate::context::supervisor::MessageSigner;

/// Alias for the broadcast channel used to fan out [`ContextEvent`]s to
/// external subscribers (webhook dispatcher, SDK event streams).
pub type ContextEventSender = tokio::sync::broadcast::Sender<(String, ContextEvent)>;

/// Default TTL (in seconds) for sealed message blobs sent through the
/// transport. 300s = 5 minutes — short enough to limit replay surface,
/// long enough to absorb transient relay outages.
///
/// Public so the lifecycle path can re-use the same value when sealing
/// welcome envelopes. Sourced from the wasm-safe
/// [`scp_protocol::envelope::outer::DEFAULT_APP_DATA_BLOB_TTL_SECS`] so the
/// native runtime and the in-browser `scp-client` driver request the identical
/// relay-storage window for the same message (ADR-057 "share, don't fork") — the
/// value is unchanged (300s); only its single source of truth moved.
pub const DEFAULT_BLOB_TTL_SECS: u32 =
    scp_protocol::envelope::outer::DEFAULT_APP_DATA_BLOB_TTL_SECS;

// ---------------------------------------------------------------------------
// 1. build_inner_wire (shared inner-envelope construction)
// ---------------------------------------------------------------------------
//
// ADR-049 PR-7 (SCP-CRYPTOMOVE-001, C8): the `#[cfg(test)]` provider seal twin
// `build_encrypted_envelope` is DELETED — its last callers (the send-path unit /
// pipeline / agent-binding fixtures) now drive the production actor seal
// `build_encrypted_envelope_actor` directly against an actor-owned
// `ContextCryptoState`. The shared inner-envelope construction below
// (`build_inner_wire`) is retained; the actor path bottoms out in it, so the
// sealed wire stays byte-identical across the flip.

/// Builds and signs the [`InnerEnvelope`] for an application-data send (access-key
/// wrap → inner-envelope stamp+sign), returning it alongside the canonical
/// 32-byte context-id digest.
///
/// Shared by both seal seams — the deleted pre-PR-7 provider path and the
/// ADR-049 PR-7 actor path ([`ContextCryptoState::seal`](crate::context::actor::state::ContextCryptoState::seal)
/// driven from the Class-C view in [`encrypt_and_send`], via
/// [`build_encrypted_envelope_actor`]) — so both bottom out in ONE
/// inner-envelope construction and the sealed wire stays byte-identical across
/// the flip (the 16 golden byte-identity tests continue to hold).
#[allow(clippy::too_many_arguments)]
fn build_inner_wire(
    clock: &Arc<dyn Clock>,
    context_id: &str,
    sender_did: &DID,
    payload: &[u8],
    signer: MessageSigner<'_>,
    recipients_data: &std::collections::HashMap<String, AccessKey>,
    sequence: u64,
    source_provenance: Option<&SourceContextInfo>,
    message_type: MessageType,
) -> Result<(InnerEnvelope, [u8; 32]), ContextError> {
    // ADR-056: key the send-path crypto by the canonical digest (matches
    // `state.context_id` and the MLS group keyed at creation), not a re-hash
    // of the hex id.
    let context_id_bytes = state::context_id_to_bytes(context_id);
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
        // ADR-039: stamp the verification method this message is signed under
        // (`#active` or `#agent`) so the recipient resolves the matching public
        // key from the sender's DID document. The stamped persona and the
        // signing key both come from the single `MessageSigner` below, so they
        // cannot disagree — no longer hardcoded to `#active`.
        signing_key_id: signer.signing_key_id(),
    };

    let inner = crate::envelope::inner::sign::create_inner_envelope_raw(&params, signer.key())
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    Ok((inner, context_id_bytes))
}

/// Builds and seals an application-data send through the ADR-049 PR-7 actor
/// crypto state (Class-C `&mut ContextCryptoState`), the field-granular crypto
/// sub-state reached via `ClassCMut::mode_mut()`. Byte-identical to the deleted
/// pre-PR-7 provider seal path: it shares [`build_inner_wire`] and
/// passes the same all-zero app-data `routing_id`, `DEFAULT_BLOB_TTL_SECS`, and
/// the caller-supplied `aad_sequence` (the authoritative sender-layer AAD
/// sequence — today `MembershipState::next_sequence_number`, matching what the
/// provider's `seal` derived from the inner envelope). `local_did` is sourced
/// from `deps.crypto.local_did()` so the sealed sender-layer AAD binds the same
/// local identity the provider used.
#[allow(clippy::too_many_arguments)]
// ADR-049 PR-7 (SCP-CRYPTOMOVE-001): widened from module-private so the relocated
// app-data send-path callers (crypto/mls/provider.rs `encrypt_and_send`, plus the
// agent_binding_pipeline_tests) can drive the PRODUCTION actor app-data seal — the
// one that zeroes the outer `routing_id` (§9.10.4) — after the deleted provider
// twin `build_encrypted_envelope` is removed. `pub(crate)` is the minimal correct
// visibility: callers span `crypto/mls/provider.rs` and `context/`, so a
// `pub(super)` / `pub(in crate::context)` cap would wrongly forbid the crypto/mls
// caller (E0624). It is a purely internal crate seam with no FFI/SDK surface, so it
// carries no cross-layer bridge-export requirement. `redundant_pub_crate` is a
// false positive here for the same reason as `Supervisor::build_actor_deps`: the
// enclosing module is `pub(crate)`, but the item is genuinely reached crate-wide.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn build_encrypted_envelope_actor(
    clock: &Arc<dyn Clock>,
    crypto_state: &mut crate::context::actor::state::ContextCryptoState,
    local_did: &str,
    context_id: &str,
    sender_did: &DID,
    payload: &[u8],
    signer: MessageSigner<'_>,
    recipients_data: &std::collections::HashMap<String, AccessKey>,
    aad_sequence: u64,
    source_provenance: Option<&SourceContextInfo>,
    message_type: MessageType,
) -> Result<Vec<u8>, ContextError> {
    let (inner, context_id_bytes) = build_inner_wire(
        clock,
        context_id,
        sender_did,
        payload,
        signer,
        recipients_data,
        aad_sequence,
        source_provenance,
        message_type,
    )?;
    // §9.10.4 privacy: app-data outer `routing_id` is the 32-byte zero sentinel
    // — one sealed blob fans out to N per-member pseudonym transport addresses,
    // so no single per-recipient value belongs here, and embedding the
    // relay-derivable `context_routing_id` would leak a correlator to the relay.
    // The all-zero value is a RESERVED/forbidden pseudonym that cannot collide
    // with a real routing ID; the receiver routes on the transport key and never
    // reads this field for app-data.
    let routing_id = [0u8; 32];
    crypto_state.seal(
        &context_id_bytes,
        local_did,
        &inner,
        &routing_id,
        DEFAULT_BLOB_TTL_SECS,
        aad_sequence,
    )
}

// ---------------------------------------------------------------------------
// 2. enforce_send_economy
// ---------------------------------------------------------------------------

/// Enforces economic policy for message sends (#1537, #1593).
///
/// Actor-shape variant: takes the [`ClassSCell`](crate::context::actor::class_s::ClassSCell)
/// and routes the spending-nonce consume through
/// [`begin_class_s_conditional`](crate::context::actor::class_s::ClassSCell::begin_class_s_conditional)
/// so the consume is DEFERRED-persisted (ADR-049 §9, keep-direction). The
/// returned [`ClassSCommitToken`](crate::context::actor::class_s::ClassSCommitToken)
/// is `Some` ONLY on the PAID branch (a non-zero cost was charged AND a spending
/// UCAN was presented — i.e. `enforce_economy` actually burned a nonce); the
/// free / best-effort branch returns `None` so the caller's existing best-effort
/// persist is kept. `send_message` threads the token down to `finalize_send`,
/// which discharges it (or each early-abort path commits it before its
/// Class-C reversal).
pub fn enforce_send_economy(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    sender_did: &DID,
    now: u64,
    spending_ucan: Option<&UcanToken>,
    context_id: &str,
    clock: &dyn Clock,
    key_resolver: &KeyResolver,
) -> Result<
    (
        Option<scp_protocol::economy::types::Amount>,
        Option<crate::context::actor::class_s::ClassSCommitToken>,
    ),
    ContextError,
> {
    cell.begin_class_s_conditional(context_id, |mut view| {
        let state = view.rest_mut();
        let pricing_default =
            scp_protocol::economy::antispam::ContextMessagePricingConfig::spec_default();
        let member_count = state.membership.count();
        let governance = &mut state.governance;
        let pricing = governance
            .message_pricing
            .as_ref()
            .unwrap_or(&pricing_default);
        let cost = crate::context::economy_logic::enforce_economy(
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
                nonce_tracker: &mut governance.class_s.spending_nonce_tracker,
                revoked_spending_ucan_cids: &governance.revoked_spending_ucan_cids,
                key_resolver,
            },
        )?;
        // A spending-UCAN nonce is burned (Class-S consume) iff `enforce_economy`
        // charged a non-zero cost AND a spending UCAN was presented — the same
        // gating the deferred fail-closed persist uses. The free / zero-cost
        // branch burns no nonce, so it issues no token.
        let did_consume_nonce = cost.is_some() && spending_ucan.is_some();
        Ok((cost, did_consume_nonce))
    })
}

/// Discharge a deferred spending-nonce [`ClassSCommitToken`](crate::context::actor::class_s::ClassSCommitToken) on a `send_message`
/// EARLY-ABORT path (ADR-049 §9, keep-direction) and return the error to
/// propagate.
///
/// The early-abort paths in `send_message` occur AFTER `enforce_send_economy`
/// burned the spending-UCAN nonce but BEFORE `finalize_send`. The burned nonce
/// MUST be persisted fail-closed on these paths too (keep-direction: a crash in
/// the coalesce window must not un-burn it and re-open replay), so each commits
/// the token here BEFORE its existing escrow-void + economy-ticket rollback.
///
/// Returns the error the abort path should propagate:
/// - token `None` (the consume did not happen — free / pre-consume abort) ⇒ the
///   original `abort_err` unchanged;
/// - token `Some` and its fail-closed persist SUCCEEDS ⇒ the original
///   `abort_err` (the consume is now durable; the send still aborts for its own
///   reason);
/// - token `Some` and its fail-closed persist FAILS ⇒ the
///   [`ContextError::PersistenceFailed`] (fail-closed: a durability failure of
///   the burned nonce takes precedence, mirroring `finalize_send`'s persist-fail
///   arm). The consume is KEPT in memory either way.
///
/// The caller runs its existing Class-C reversal (escrow void, ticket rollback,
/// sequence rollback) AFTER this returns, regardless of which error comes back.
///
/// Shared with the join path (`lifecycle_helpers::join_context`), whose
/// pre-finalize abort paths have the identical keep-direction obligation.
///
/// Internal cross-module helper — `pub` only so the sibling `crate::context`
/// dispatch modules can call it; not part of the SDK surface.
///
/// # Not `async fn` — `Send` discipline (ADR-049 Decision 7)
///
/// SYNC fn returning a future: [`ClassSCommitToken::commit`](crate::context::actor::class_s::ClassSCommitToken::commit) is itself a
/// sync-returns-future that consumes the `&PerContextState` in its prelude, so
/// the returned future here captures only the (already state-free) commit future
/// plus the owned `abort_err`. An `async fn` would keep the `&PerContextState`
/// parameter across the await and make the awaiting handler `!Send`.
pub fn commit_send_nonce_token_on_abort<'d, 'c>(
    token: Option<crate::context::actor::class_s::ClassSCommitToken>,
    state: &PerContextState,
    deps: &'d ActorDeps,
    context_id: &'c str,
    abort_err: ContextError,
) -> impl std::future::Future<Output = ContextError> + Send + use<'d, 'c> {
    // `t.commit(...)` runs its snapshot-building prelude synchronously here
    // (consuming the `&PerContextState`) and yields a state-free `Send` future.
    let commit_fut = token.map(|t| t.commit(state, deps, context_id));
    async move {
        match commit_fut {
            None => abort_err,
            Some(fut) => match fut.await {
                Ok(()) => abort_err,
                Err(persist_err) => persist_err,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// 3. build_broadcast_envelope
// ---------------------------------------------------------------------------

/// Builds a broadcast envelope for the send path. Pure helper.
pub fn build_broadcast_envelope(
    clock: &dyn Clock,
    bc: &mut BroadcastContextClassCMut<'_>,
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
    // ADR-039: resolve the verification method the sender declared in the
    // inner envelope (`#active` or `#agent`), so an `#agent`-signed message is
    // verified against the agent key and an `#active`-signed one against the
    // human key. The resolver returns `None` when that specific VM is absent
    // from the sender's DID document (e.g. `#agent` requested but never added).
    let signing_key_id = inner.signing_key_id;
    let public_key = (key_resolver)(&DID(sender_did.to_owned()), signing_key_id).ok_or_else(|| {
        ContextError::CryptoFailed(format!(
            "cannot resolve public key for sender {sender_did} verification method {signing_key_id}"
        ))
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
    view: &mut ClassCMut,
    sender_did: &str,
    plaintext: &[u8],
    context_id: &str,
    event_tx: Option<&ContextEventSender>,
) -> Option<scp_event_log::EventType> {
    // §9.10.4: run the shared announcement-ingest validator. The buffered path
    // maps a rejection to `None` (silent drop) — the message has already been
    // buffered/reordered, so there is no caller to return a typed error to.
    match ingest_pseudonym_announcement(view, sender_did, plaintext, context_id, event_tx) {
        AnnouncementOutcome::Recorded => {
            tracing::debug!(
                context_id,
                sender_did,
                "processed buffered pseudonym announcement"
            );
            // A received pseudonym announcement is a §9.10.4 routing-bootstrap
            // signal, NOT a durable Merkle event. `ingest_pseudonym_announcement`
            // already inserted the peer's routing ID into the in-memory registry
            // and — when the value was new or changed (emit-on-change) — emitted
            // `ContextEvent::PseudonymAnnounced` to the receive buffer (the
            // announcement's entire function). Returning `None`
            // suppresses any durable append, exactly as for received application
            // messages (`NotAnnouncement` below): a per-receiver, per-arrival-order
            // append cannot converge across honest members (late joiners miss
            // earlier announcements; honest members never append on receive),
            // which would false-positive §9.9.3 equivocation detection.
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
            emit_event_into(view.receive_buffer_mut(), event, context_id, event_tx);
            None
        }
    }
}

// ---------------------------------------------------------------------------
// §9.10.4 announcement / routing helpers
// ---------------------------------------------------------------------------

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
    /// the peer registry was updated. A `PseudonymAnnounced` event is emitted
    /// only when the recorded pseudonym was NEW or CHANGED (emit-on-change) —
    /// an identical re-announce records the (unchanged) value and emits nothing.
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
    view: &mut ClassCMut,
    sender_did: &str,
    plaintext: &[u8],
    context_id: &str,
    event_tx: Option<&ContextEventSender>,
) -> AnnouncementOutcome {
    // Run the shared, wasm-safe §9.10.4 decision core over the immutable peer
    // registry (`None` for a broadcast context). The classifier owns the
    // four-step validation; the native side effects — the rejection metric, the
    // per-branch `tracing` warn, the registry insert, and the `PseudonymAnnounced`
    // buffer emit — stay HERE and are byte-and-trace-identical to the previous
    // inline implementation.
    // S1 own-pseudonym guard (centralized in the shared classifier — ADR-057): pass
    // this member's OWN pseudonym so a forged `attacker_did → our_pseudonym`
    // announcement is rejected as a collision. `local_pseudonym()` and
    // `peer_registry()` both read the routing state; capture the local pseudonym
    // first so the two borrows do not overlap.
    let local_pseudonym = view.routing_mut().local_pseudonym();
    match classify_pseudonym_announcement(
        plaintext,
        sender_did,
        context_id,
        view.routing_mut().peer_registry(),
        local_pseudonym,
    ) {
        PseudonymAnnouncementDecision::NotAnnouncement => AnnouncementOutcome::NotAnnouncement,
        PseudonymAnnouncementDecision::Rejected {
            reason,
            claimed_did,
        } => {
            crate::metrics::record_pseudonym_announcement_rejected();
            // Reproduce the exact warn that fired before for each rejection
            // branch. The sender-mismatch branch is the ONLY one carrying a
            // `claimed_did`, and it logs it as a field (`%claimed_did` renders
            // the raw DID string, identical to the prior `%announcement.member_did`);
            // the other three branches are disambiguated by their stable reason.
            if let Some(claimed_did) = claimed_did {
                tracing::warn!(
                    context_id,
                    sender_did,
                    claimed_did = %claimed_did,
                    "pseudonym announcement sender mismatch — rejecting forged announcement"
                );
            } else if reason == pseudonym::REJECT_RESERVED {
                tracing::warn!(
                    context_id,
                    sender_did,
                    "pseudonym announcement uses a reserved routing ID — rejecting"
                );
            } else if reason == pseudonym::REJECT_BROADCAST {
                tracing::warn!(
                    context_id,
                    sender_did,
                    "pseudonym announcement received on broadcast context — rejecting"
                );
            } else {
                tracing::warn!(
                    context_id,
                    sender_did,
                    "pseudonym announcement collides with another member's routing ID — rejecting"
                );
            }
            AnnouncementOutcome::Rejected(reason)
        }
        PseudonymAnnouncementDecision::Accept {
            member_did,
            pseudonym,
        } => {
            // The classifier only returns `Accept` for an encrypted context whose
            // peer registry is present and non-colliding; re-borrow it mutably to
            // insert. The `if let` (rather than a workspace-denied `expect`) is a
            // total match over that proven invariant — the registry presence
            // cannot change between the classify read and this insert (no mutation
            // occurs in between). `HashMap::insert` returns the PRIOR value, which
            // drives the emit-on-change predicate below.
            let previous = view
                .routing_mut()
                .peer_registry_mut()
                .and_then(|registry| registry.insert(member_did.clone(), pseudonym));
            // Record + emit-ON-CHANGE. Emit the `PseudonymAnnounced` observability
            // event only when the recorded pseudonym is NEW **or CHANGED** — a
            // first-contact peer, or a KNOWN peer that rotated its pseudonym and
            // re-announced a different value (surfacing the routing change to a
            // stream watcher). An IDENTICAL re-announce leaves the registry value
            // unchanged and emits nothing, deduping the mesh's reciprocal-cascade
            // re-sends. This mirrors the browser client's ingest predicate
            // (`scp-client` `ingest_application_plaintext`) so accept/emit cannot
            // drift across targets (share-don't-fork). The `routing_mut()` borrow
            // above has ended (NLL) before this disjoint `receive_buffer` emit.
            if previous != Some(pseudonym) {
                let event = ContextEvent::PseudonymAnnounced {
                    member_did,
                    pseudonym,
                };
                emit_event_into(view.receive_buffer_mut(), event, context_id, event_tx);
            }
            AnnouncementOutcome::Recorded
        }
    }
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
///
/// Arms `obligation` (the caller's `&mut Option<ClassSCommitToken>` sink) iff
/// consequence enforcement performed a downward-authorization mutation (a
/// `suspended_capabilities` GROW or an `AssignRole` `member_capabilities`
/// replacement) — the GROW methods do the arming, so it cannot be forgotten
/// (ADR-049 §9, RED-CS3, GAP-A). The cell holder discharges the populated sink
/// fail-closed after the borrowing view drops; evaluation otherwise stays
/// best-effort / coalesced. The returned `bool` mirrors whether the sink was
/// armed (retained as the RED-CS3b engine signal for callers that observe it).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub async fn run_buffered_post_delivery(
    view: &mut ClassCMut<'_>,
    obligation: &mut Option<crate::context::actor::class_s::ClassSCommitToken>,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    sender_did: &str,
    event_name: Option<scp_event_log::EventType>,
    // Committer-assigned leaf timestamp copied from the inbound message
    // envelope's `created_at` (seconds), for the sender-authenticated received
    // event the `Some(event_name)` branch would append. It would be convergent
    // by copy — never a per-member local `now()` (§7.3.1, §9.9.3).
    //
    // DORMANT: every current caller passes `event_name = None`, so this
    // timestamp is not yet consumed — the receive-side append branch that
    // would replicate a committer's leaf onto a receiving member's log is not
    // wired. Until that lands (the cross-member leaf-replication forward step
    // under ADR-051), membership/governance leaves remain committer-appended
    // only and do NOT converge cross-member. Do not assume this value is live.
    event_timestamp_secs: u64,
    clock: &dyn Clock,
    event_log: &dyn crate::context::builder::ContextEventLogProvider,
    event_tx: Option<&ContextEventSender>,
) -> bool {
    let now = clock.now_secs();

    // Velocity tracking — always record for buffered messages.
    view.governance_class_c_mut()
        .velocity_tracker_mut()
        .record_message(&DID(sender_did.to_owned()), now);

    // Durable Merkle append ONLY for sender-authenticated events. Application
    // messages (`None`) skip the append but still run governance below.
    if let Some(event_name) = event_name
        && let Err(e) = event_log
            .append_context_event(
                context_id_bytes,
                event_name,
                sender_did,
                event_timestamp_secs,
            )
            .await
    {
        tracing::warn!(
            context_id,
            sender_did,
            event_name = ?event_name,
            "failed to append buffered event to event log: {e}"
        );
    }

    let consequence_rules: Vec<ConsequenceRule> = view
        .governance_class_c_mut()
        .consequence_rules_mut()
        .clone();
    // ADR-049 §9 (RED-CS3): `true` iff consequence enforcement performed a
    // downward-authorization mutation on this delivery (a capability suspension
    // or an `AssignRole` demotion) — propagated to the cell-holding caller so the
    // mutation persists fail-closed (keep-direction).
    let downward_auth_applied = if consequence_rules.is_empty() {
        false
    } else {
        let (events, convergent_now) =
            crate::context::governance_logic::event_log_entries_for_consequences(
                view.receive_buffer_mut(),
                context_id,
                now,
                event_log,
            );
        let triggered = evaluate_consequence_rules(
            &consequence_rules,
            &events,
            sender_did,
            now,
            convergent_now,
        );
        let member_did = DID(sender_did.to_owned());
        // The `receive_buffer` read above has ended (NLL) before `consequence_split`
        // reborrows the disjoint consequence fields (incl. the GROW role view).
        let mut split = view.consequence_split();
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
            obligation,
        )
        .await
    };

    *view.checkpoint_events_since_mut() += 1;
    downward_auth_applied
}

// ---------------------------------------------------------------------------
// 7. send_message (top-level, actor-shape)
// ---------------------------------------------------------------------------

/// Discharges a [`send_message`] Phase-1 routing/envelope ABORT (ADR-049 §9,
/// keep-direction): persists the burned spending-nonce token FAIL-CLOSED (a
/// Class-S obligation owed on every terminal path, via a SHARED
/// `&PerContextState` auto-derefed from `cell`) BEFORE reversing the Class-C
/// economy ticket through a fresh `ClassCMut` governance view, then returns the
/// (possibly persist-promoted) error.
///
/// Each call site has ALREADY reversed its own sequence reservation (or reserved
/// none) inside the view before invoking this — so this helper never touches the
/// per-sender sequence. Returns the original `abort_err` when the token persists
/// cleanly (or no token was burned), or the [`ContextError::PersistenceFailed`]
/// when the fail-closed persist of the burned nonce itself fails.
async fn discharge_send_abort(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    token: Option<crate::context::actor::class_s::ClassSCommitToken>,
    ticket: crate::context::economy_logic::EconomyTicket,
    abort_err: ContextError,
) -> Result<(), ContextError> {
    let err = commit_send_nonce_token_on_abort(token, cell, deps, context_id, abort_err).await;
    crate::context::economy_logic::rollback_economy_ticket_inline_view(
        cell.class_c_view().governance_class_c_mut(),
        ticket,
    );
    Err(err)
}

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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    handle: &ContextHandle,
    sender_did: &DID,
    payload: &[u8],
    signing_key: Option<&ed25519_dalek::SigningKey>,
    signing_key_id: SigningKeyId,
    source_provenance: Option<&SourceContextInfo>,
    spending_ucan: Option<&UcanToken>,
) -> Result<(), ContextError> {
    let context_id = handle.context_id().to_owned();
    // ADR-056: canonical digest, not a re-hash of the hex id.
    let context_id_bytes = state::context_id_to_bytes(&context_id);

    // Pre-economy active + commit-fault gates run FIRST (matching the legacy
    // ordering: `require_active` → `check_commit_fault_marker` → signer-`None` →
    // capability → rate-limit), so the surfaced error precedence on a
    // multiply-invalid call is unchanged. Both reads run through a short-lived
    // non-persisting Class-C view whose `&mut` borrow ends (NLL) before the
    // signer match below.
    {
        let mut view = cell.class_c_view();
        state::require_active(view.handle_mut())?;
        // Fail-close on commit fault.
        governance_helpers::check_commit_fault_marker(view.commit_fault_mut().as_ref())?;
    }

    // ADR-039: pair the signing key with its persona into a single
    // `MessageSigner` up front — both the broadcast envelope build and the
    // encrypted stamp+sign site below read the key and the stamped
    // verification method from this one value, so they cannot disagree. Every
    // send path requires a key; a missing one is rejected here, fail-closed,
    // BEFORE any rate-limit / velocity / economy state is mutated (so no
    // rollback is needed). Both encrypted and broadcast sends previously
    // re-checked `None` downstream; this single check subsumes them.
    let signer = match signing_key {
        Some(sk) => match signing_key_id {
            SigningKeyId::Active => MessageSigner::Active(sk),
            SigningKeyId::Agent => MessageSigner::Agent(sk),
        },
        None => {
            return Err(ContextError::CryptoFailed(
                "signing key required for send".into(),
            ));
        }
    };

    // ADR-049 §9 Class-S cell seam: the pre-economy gate runs through the
    // non-persisting Class-C view (the `&mut view` borrow ends — NLL — before
    // the cell-taking `enforce_send_economy` leaf). Each gate/mutation is
    // Class-C / structural (capability read, hard-rate-limit consume, velocity
    // record); the spending-nonce consume itself is the only Class-S mutation
    // and lives in `enforce_send_economy`.
    let now_secs = deps.clock.now_secs();
    let velocity_token = {
        let mut view = cell.class_c_view();
        // H7: capability check BEFORE budget deduction.
        if view.broadcast_class_c_mut().is_none() {
            let role = view.role_state_class_c_mut();
            if !role.member_has_capability(sender_did.as_ref(), &Capability::MessagesWrite) {
                let is_suspended = role
                    .suspended_capabilities()
                    .get(sender_did.as_ref())
                    .is_some_and(|s| s.contains(&Capability::MessagesWrite));
                let msg = if is_suspended {
                    format!("member {sender_did} write access has been revoked")
                } else {
                    format!("member {sender_did} does not have messages:write capability")
                };
                return Err(ContextError::PermissionDenied(msg));
            }
        }
        // Hard rate limit consume — defense-in-depth.
        if !view
            .governance_class_c_mut()
            .hard_rate_limit_mut()
            .try_consume(sender_did, now_secs)
        {
            return Err(ContextError::RateLimited {
                resource: "send".to_owned(),
                message: "hard rate limit exceeded for sender".to_owned(),
                // Token-bucket hard limit: no exact refill instant to surface.
                retry_after_ms: None,
            });
        }
        // M4: record velocity BEFORE economy enforcement.
        view.governance_class_c_mut()
            .velocity_tracker_mut()
            .record_message(sender_did, now_secs)
    };

    // `enforce_send_economy` is the spending-nonce-bearing leaf and takes the
    // cell; the view borrow above has ended (NLL) so `cell` is free here.
    // `enforce_send_economy` routes the spending-nonce consume through the
    // DEFERRED-persist combinator (ADR-049 §9): it returns the cost plus an
    // `Option<ClassSCommitToken>` that is `Some` only on the PAID (nonce-burning)
    // branch. That token's fail-closed persist is owed on EVERY terminal path
    // below (keep-direction) — the Err arm here issues NO token (nothing was
    // consumed), so it is unchanged.
    let (deducted_cost, mut spending_nonce_token) = match enforce_send_economy(
        cell,
        sender_did,
        now_secs,
        spending_ucan,
        &context_id,
        &*deps.clock,
        &deps.key_resolver,
    ) {
        Ok(cost_and_token) => cost_and_token,
        Err(e) => {
            // Roll back velocity + hard-rate-limit. No EconomyTicket exists yet;
            // rollback inline through the non-persisting Class-C governance view.
            // No token was issued (the consume did not happen), so nothing to
            // commit.
            let mut view = cell.class_c_view();
            let gov = view.governance_class_c_mut();
            gov.velocity_tracker_mut()
                .rollback(sender_did, velocity_token);
            gov.hard_rate_limit_mut().refund(sender_did);
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

    // Phase 1 routing/envelope build runs through the non-persisting Class-C
    // view. An abort here owes the keep-direction nonce-token persist (Class-S,
    // FAIL-CLOSED via `&*cell`) BEFORE its Class-C reversal — but the token
    // commit needs a SHARED `&PerContextState` that cannot overlap the `&mut
    // view`. So the view block computes the routing tuple OR a typed
    // [`SendAbort`] carrying the error and whether the sequence was reserved; the
    // abort is then discharged AFTER the view borrow ends (NLL), committing the
    // token through `&*cell` and reversing the economy ticket / sequence through
    // a fresh view.
    // The view block computes the routing tuple OR returns a typed `Err` carrying
    // the abort error. Each abort variant fully reverses its OWN Class-C side
    // effects inside the view (the `PseudonymRegistryEmpty` arm rolls the reserved
    // sequence; the others reserved none). The abort is discharged AFTER the view
    // borrow ends (NLL): the keep-direction nonce-token persist needs a SHARED
    // `&PerContextState` (auto-derefed from `cell`) that cannot overlap the
    // `&mut view`, and the economy-ticket reversal takes a fresh view.
    #[allow(clippy::type_complexity)]
    let routing: Result<
        (
            Option<BroadcastEnvelope>,
            std::collections::HashMap<String, AccessKey>,
            u64,
            bool,
            Vec<[u8; 32]>,
        ),
        ContextError,
    > = {
        let mut view = cell.class_c_view();
        if let Some(mut bc) = view.broadcast_class_c_mut() {
            // `signer` was validated non-`None` at the top of the function; the
            // broadcast envelope is signed with the same key the encrypted path
            // would stamp, sourced from the one `MessageSigner`.
            build_broadcast_envelope(&*deps.clock, &mut bc, sender_did, payload, signer.key()).map(
                |env| {
                    // Broadcast: SHA-256(context_id) per spec §5.14.
                    let broadcast_rid = scp_protocol::context::broadcast_routing_id(&context_id);
                    (
                        Some(env),
                        std::collections::HashMap::new(),
                        0,
                        true,
                        vec![broadcast_rid],
                    )
                },
            )
        } else {
            // Encrypted: assign sequence under actor-owned tracker.
            let Some(seq) = view
                .membership_class_c_mut()
                .next_sequence_number(sender_did)
            else {
                return discharge_send_abort(
                    cell,
                    deps,
                    &context_id,
                    spending_nonce_token.take(),
                    ticket,
                    ContextError::MemberNotFound(format!(
                        "cannot assign sequence: {sender_did} is not a member"
                    )),
                )
                .await;
            };
            // §9.10.4: encrypted contexts fan out to each member's pseudonym
            // routing ID. App data embeds NO correlating routing value: the outer
            // envelope's cleartext `routing_id` is the all-zero sentinel (set in
            // `build_encrypted_envelope`), and the transport address is the
            // per-member pseudonym. The shared `context_routing_id` — which a relay
            // can derive from the public context ID — appears in neither the
            // envelope field nor the transport address for application data, so a
            // relay cannot read a shared correlator off app-data blobs.
            //
            // KNOWN LIMITATION (§9.10.4): the ONE remaining residual is that
            // fan-out sends the SAME MLS ciphertext to all per-member pseudonym
            // addresses. A relay can still correlate pseudonyms by blob-matching
            // (observing identical encrypted blobs across addresses). This is not
            // full unlinkability. Per-recipient re-encryption would fix it but
            // increases bandwidth by O(N); deferred to relay-blinding, which
            // §9.10.4 already documents.
            //
            // Announcement bootstrap channel: `PseudonymAnnouncement` payloads are
            // the ONLY messages permitted to use the shared routing ID, and they go
            // there EXCLUSIVELY — never unioned with peer pseudonyms. Every member
            // subscribes to the shared RID for MLS management traffic, so a single
            // publish reaches every current subscriber regardless of whether we
            // have learned their pseudonym yet. App data continues to fan out to
            // known peer pseudonyms only.
            //
            // Invariant: this branch is the `else` of `broadcast_context.is_some()`,
            // so routing must be pseudonymous.
            let routing_is_broadcast = view.routing_mut().is_broadcast();
            debug_assert!(
                !routing_is_broadcast,
                "send fan-out reached the pseudonymous branch with broadcast routing"
            );
            let is_announcement = is_pseudonym_announcement_payload(payload);
            let member_count = view.membership_class_c_mut().count();
            if is_announcement {
                // Bootstrap path: address the shared RID ONLY.
                let routing_ids = vec![scp_protocol::context::context_routing_id(&context_id)];
                let recipients = view.access_mut().access_key_store.get_all(&context_id);
                Ok((None, recipients, seq, false, routing_ids))
            } else {
                let peer_pseudonyms: Vec<[u8; 32]> = view
                    .routing_mut()
                    .peer_registry()
                    .map(|reg| reg.values().copied().collect())
                    .unwrap_or_default();
                if member_count > 1 && peer_pseudonyms.is_empty() {
                    // App-data send into an encrypted multi-member context with an
                    // empty pseudonym registry would produce zero sends and silently
                    // drop the payload — masking a bidirectional bootstrap deadlock.
                    // Raise a typed error so callers can distinguish "peers have not
                    // announced yet; retry later" from a transport failure, and roll
                    // back the economy ticket + sequence reservation. The sequence
                    // reservation IS rolled back here (it was taken above), so the
                    // discharge must NOT roll it again — hence the explicit reversal
                    // here rather than relying on the (sequence-agnostic) discharge.
                    //
                    // Ordering note: the rollback runs HERE (inside the `&mut view`)
                    // BEFORE the keep-direction nonce persist in `discharge_send_abort`
                    // (which needs a non-overlapping `&*cell` shared borrow), so the
                    // persisted snapshot reflects the rolled-BACK (reusable) sequence.
                    // This is safe: the message was never transmitted, and the
                    // per-sender outbound counter only needs monotonicity for sequences
                    // actually sent — persisting the reusable value cannot reorder or
                    // replay a delivered message.
                    view.membership_class_c_mut()
                        .rollback_sequence_number(sender_did);
                    let err = ContextError::PseudonymRegistryEmpty {
                        context_id: context_id.clone(),
                        member_count,
                    };
                    // `view`'s last use is the sequence rollback above; its borrow
                    // ends here (NLL) so `cell` is free for the discharge below.
                    return discharge_send_abort(
                        cell,
                        deps,
                        &context_id,
                        spending_nonce_token.take(),
                        ticket,
                        err,
                    )
                    .await;
                }
                let recipients = view.access_mut().access_key_store.get_all(&context_id);
                Ok((None, recipients, seq, false, peer_pseudonyms))
            }
        }
    };
    let (broadcast_envelope, recipients_data, sequence, is_broadcast, send_routing_ids) =
        match routing {
            Ok(tuple) => tuple,
            Err(err) => {
                return discharge_send_abort(
                    cell,
                    deps,
                    &context_id,
                    spending_nonce_token.take(),
                    ticket,
                    err,
                )
                .await;
            }
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
        // Keep-direction (ADR-049 §9): even on this no-charge no-op exit, a
        // spending-UCAN nonce burned in Phase 1 MUST persist fail-closed — a
        // crash in the coalesce window must not un-burn it and re-open replay.
        // Commit the token first; if its persist fails, surface that error
        // (fail-closed) instead of the no-op `Ok(())`. The Class-C reversal
        // (ticket + sequence) runs regardless.
        // The token's `commit` takes a SHARED `&PerContextState` (via `&*cell`).
        let nonce_persist = match spending_nonce_token.take() {
            Some(t) => t.commit(cell, deps, &context_id).await,
            None => Ok(()),
        };
        crate::context::economy_logic::rollback_economy_ticket_inline_view(
            cell.class_c_view().governance_class_c_mut(),
            ticket,
        );
        cell.class_c_view()
            .membership_class_c_mut()
            .rollback_sequence_number(sender_did);
        return nonce_persist;
    }

    // Payment flow: authorize (hold) before action. The sync PREPARE reads the
    // SHARED `&PerContextState` (via `&*cell`) and its borrow drops at the call
    // boundary (the result is owned); the async HOLD then awaits with NO cell
    // borrow held — so the actor future stays `Send` (`ClassSCell` is not `Sync`,
    // so a `&ClassSCell` held across the await would poison it).
    let auth = match authorize_send_payment_prepare(&*cell, deps, sender_did) {
        None => None,
        Some(inputs) => match crate::context::economy_helpers::authorize_paid_action_hold(
            inputs,
            sender_did,
            &context_id,
        )
        .await
        {
            Ok(auth) => auth,
            Err(e) => {
                // Keep-direction (ADR-049 §9): persist the burned nonce fail-closed
                // (via `&*cell`) before the existing Class-C reversal.
                let err = commit_send_nonce_token_on_abort(
                    spending_nonce_token.take(),
                    cell,
                    deps,
                    &context_id,
                    e,
                )
                .await;
                crate::context::economy_logic::rollback_economy_ticket_inline_view(
                    cell.class_c_view().governance_class_c_mut(),
                    ticket,
                );
                if !is_broadcast {
                    cell.class_c_view()
                        .membership_class_c_mut()
                        .rollback_sequence_number(sender_did);
                }
                return Err(err);
            }
        },
    };

    // Phase 2: encrypt + send.
    //
    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): seal through the actor's field-granular
    // Class-C `&mut ContextCryptoState` (reached via `mode_mut().crypto_mut()`).
    // Broadcast contexts have no crypto sub-state, so `crypto_mut()` is `None` and
    // the broadcast branch of `encrypt_and_send` builds the wire without it. The
    // `&mut` view is scoped to just this call so `cell` is free for the abort /
    // finalize arms below (NLL). Holding a `&mut ContextCryptoState` across the
    // fan-out await is `Send` (mirrors `handle_deliver_incoming`'s `class_c_view`
    // held across its timeout await).
    let phase2_result = {
        let mut view = cell.class_c_view();
        let crypto_state = view.mode_mut().crypto_mut();
        encrypt_and_send(
            deps,
            crypto_state,
            broadcast_envelope,
            signer,
            &context_id,
            sender_did,
            payload,
            &recipients_data,
            sequence,
            source_provenance,
            &send_routing_ids,
            MessageType::Content,
        )
        .await
    };
    if let Err(e) = phase2_result {
        // Keep-direction (ADR-049 §9): persist the burned nonce fail-closed
        // (via `&*cell`) BEFORE the existing escrow-void + ticket rollback. If the
        // persist fails, surface that error (fail-closed); the Class-C reversal
        // runs either way.
        let err = commit_send_nonce_token_on_abort(
            spending_nonce_token.take(),
            cell,
            deps,
            &context_id,
            e,
        )
        .await;
        // Void escrow + roll back ticket on send failure.
        if let Some(a) = auth {
            crate::context::economy_helpers::void_paid_action(deps, a, &context_id).await;
        }
        crate::context::economy_logic::rollback_economy_ticket_inline_view(
            cell.class_c_view().governance_class_c_mut(),
            ticket,
        );
        if !is_broadcast {
            cell.class_c_view()
                .membership_class_c_mut()
                .rollback_sequence_number(sender_did);
        }
        return Err(err);
    }

    // Phase 3: finalize, then capture escrow + commit ticket.
    //
    // ADR-049 §9 Class S (BLACK-001): the spending-nonce consume that
    // `enforce_send_economy` performed in Phase 1 mutated the actor-owned
    // `spending_nonce_tracker` — security-critical monotonic state that does
    // NOT survive an actor crash. It MUST be durably persisted (fail-closed)
    // BEFORE this paid send is acknowledged to the caller, exactly as the
    // structurally-identical OUTLET-INVOKE path does in `reserve_outlet_economy`.
    // A best-effort (coalesced) persist would let an actor crash in the ≤50ms
    // coalesce window roll the consume back, freshening the spending UCAN's
    // nonce after the caller already saw the send succeed — a replay /
    // double-spend window. `finalize_send` therefore persists fail-closed when
    // a spending nonce was committed for THIS send (mirroring the exact gating
    // `reserve_outlet_economy` uses: `deducted_cost.is_some() &&
    // spending_ucan.is_some()`); on persist failure it returns an error and we
    // REVERSE the economy reservation (budget / velocity / rate-limit) and void
    // the escrow hold below — leaving the consumed nonce CONSUMED (the
    // fail-closed direction; un-consuming would re-open the replay window) and
    // surfacing the error so the caller does not observe a phantom success.
    // Non-spending / free sends keep the best-effort persist inside
    // `finalize_send` (the common path is not regressed). The deferred
    // [`ClassSCommitToken`] carries the fail-closed-persist obligation: it is
    // `Some` exactly on the paid (nonce-burning) branch, so the assertion below
    // pins the token's presence to the legacy `deducted_cost.is_some() &&
    // spending_ucan.is_some()` gating.
    debug_assert_eq!(
        spending_nonce_token.is_some(),
        deducted_cost.is_some() && spending_ucan.is_some(),
        "spending-nonce token must be Some iff a paid send burned a nonce",
    );
    if let Err(e) = finalize_send(
        cell,
        deps,
        &context_id,
        &context_id_bytes,
        sender_did,
        sequence,
        payload,
        // Periodic checkpoints broadcast from `finalize_send` are always
        // human/device-originated `#active` signals; they need only the raw
        // key, which we hand over from the one `MessageSigner`.
        Some(signer.key()),
        spending_nonce_token.take(),
        is_broadcast,
    )
    .await
    {
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
            crate::context::economy_helpers::void_paid_action(deps, a, &context_id).await;
        }
        crate::context::economy_logic::rollback_economy_ticket_inline_view(
            cell.class_c_view().governance_class_c_mut(),
            ticket,
        );
        return Err(e);
    }

    let deducted_cost = crate::context::economy_logic::commit_economy_ticket(ticket);
    capture_send_payment(cell, deps, auth, sender_did, &context_id, deducted_cost).await;
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
///
/// `downward_auth_sink` (ADR-049 §9, RED-CS3): a `&mut Option<ClassSCommitToken>`
/// the receive cascade (in-order delivery, force-drained gaps, or timed-out-gap
/// drains) POPULATES with a fail-closed-persist obligation if consequence
/// enforcement performs a downward-authorization mutation (a capability suspension
/// or an `AssignRole` demotion). The cell-holding handler
/// ([`crate::context::actor::handlers::messaging`]) owns the `Option`, mints it
/// `None`, and — when populated — `commit`s the token (a fail-closed,
/// keep-direction persist) before acking; evaluation otherwise stays best-effort /
/// coalesced. The token carrier (vs. the prior `bool`) makes a populated-but-
/// undischarged obligation a Drop-guard PANIC in debug/CI rather than a silently
/// dropped flag.
#[allow(clippy::too_many_lines)]
pub async fn deliver_incoming(
    view: &mut ClassCMut<'_>,
    deps: &ActorDeps,
    context_id: &str,
    encrypted_blob: &[u8],
    downward_auth_sink: &mut Option<crate::context::actor::class_s::ClassSCommitToken>,
) -> Result<DeliverOutcome, ContextError> {
    // ADR-056: canonical digest (matches the MLS group / sender keys), not a
    // re-hash of the hex id.
    let context_id_bytes = state::context_id_to_bytes(context_id);

    state::require_active(view.handle_mut())?;

    // Phase 1: read local member DID + access key (lock-free local_dids).
    let local_dids = deps.local_dids.load_full();
    let local_member_did = view
        .membership_class_c_mut()
        .member_dids()
        .find(|d| local_dids.contains(*d))
        .map(std::string::ToString::to_string)
        .ok_or_else(|| {
            ContextError::CryptoFailed("no local member found in this context".into())
        })?;
    let access_key = view
        .access_mut()
        .access_key_store
        .get(context_id, &local_member_did)
        .cloned();
    drop(local_dids);

    // Phase 2: open envelope (MLS + sender key + deserialize + integrity).
    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): open through the actor's field-granular
    // Class-C `&mut ContextCryptoState` (`mode_mut().crypto_mut()`). Broadcast
    // contexts carry no crypto sub-state (`None`), matching the retained provider
    // fallback; the `&mut` view is released as soon as the sync call returns, so
    // `view` is free for the dispatch cascade below.
    let Some(opened_envelope) = decrypt_and_dispatch(
        deps,
        view.mode_mut().crypto_mut(),
        context_id,
        &context_id_bytes,
        encrypted_blob,
    )?
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
        view.role_state_class_c_mut()
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
        return deliver_checkpoint_message(view, deps, context_id, &sender_did, &plaintext);
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
    let sequence_check =
        validate_and_drain_timeouts(view, deps, context_id, &inner, now_ms, downward_auth_sink)
            .await?;

    let is_local_sender = sender_did == local_member_did;

    match sequence_check {
        SequenceCheck::Expected => {
            let consumed_as_announcement = deliver_message_and_drain_buffered(
                view,
                deps,
                context_id,
                &context_id_bytes,
                &sender_did,
                &inner,
                &plaintext,
                is_local_sender,
                downward_auth_sink,
            )
            .await?;
            if consumed_as_announcement {
                Ok(DeliverOutcome::Handled)
            } else {
                Ok(DeliverOutcome::Application((plaintext, sender_did)))
            }
        }
        SequenceCheck::Ahead { expected: _ } => {
            buffer_ahead_message(
                view,
                deps,
                context_id,
                &inner,
                &sender_did,
                &plaintext,
                now_ms,
                downward_auth_sink,
            )
            .await;
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
    view: &mut ClassCMut,
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
    // the receive buffer when divergent (tier (a) of §23.7). The receive path
    // now threads a `ClassCMut` view (from `deliver_incoming`), so it uses the
    // view entry rather than the bare-state sibling.
    crate::context::queries_helpers::compare_remote_checkpoint(
        view,
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
pub async fn encrypt_and_send(
    deps: &ActorDeps,
    crypto_state: Option<&mut crate::context::actor::state::ContextCryptoState>,
    broadcast_envelope: Option<BroadcastEnvelope>,
    signer: MessageSigner<'_>,
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
        // Broadcast: the envelope was already built and signed by
        // `build_broadcast_envelope` (which used `signer.key()`); the persona is
        // not part of the broadcast wire shape, so the signer is unused here.
        rmp_serde::to_vec_named(&envelope)
            .map_err(|e| ContextError::CryptoFailed(format!("envelope serialization: {e}")))?
    } else {
        let encrypt_start = std::time::Instant::now();
        // The key and stamped persona travel together in the one `MessageSigner`
        // straight into the single stamp+sign site, so they cannot diverge.
        //
        // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): seal through the actor's OWNED
        // field-granular Class-C `&mut ContextCryptoState`
        // ([`build_encrypted_envelope_actor`]) — every non-broadcast send seam
        // (`send_message` / `send_checkpoint` / `send_heartbeat`) now supplies it.
        // The provider `build_encrypted_envelope` twin is deleted. This else-branch
        // is only reached for a non-broadcast encrypted send (a broadcast send took
        // the pre-built-envelope branch above), so a `None` crypto state means a
        // non-broadcast context with no MLS group — fail closed.
        let cs = crypto_state.ok_or_else(|| {
            ContextError::CryptoFailed(
                "no MLS crypto state for encrypted send (non-broadcast context has no group)"
                    .to_string(),
            )
        })?;
        let result = build_encrypted_envelope_actor(
            &deps.clock,
            cs,
            deps.crypto.local_did(),
            context_id,
            sender_did,
            payload,
            signer,
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
        match deps.transport.send_message(rid, &encrypted).await {
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

/// Broadcasts a signed [`ConsistencyCheckpoint`](scp_event_log::checkpoint::ConsistencyCheckpoint) to context peers so they can
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
// ADR-049 PR-7 (inquisitor item 8): narrowed `pub` → `pub(crate)`. The only
// callers of this FREE function are in-crate actor handlers (the reconnection
// driver in `handlers/messaging.rs` and `finalize_send` here); cross-crate code
// reaches checkpoint sending through the distinct `Supervisor::send_*` methods,
// never this helper. `pub(crate)` is the minimal correct visibility, and it keeps
// this internal seam out of the source-text `check-cross-layer` gate at the root
// (no FFI/SDK surface, no bridge-export obligation) with no PR-body exemption.
// `redundant_pub_crate` is a false positive: the enclosing `messaging_helpers`
// module is already `pub(crate)`, but this item is genuinely reached crate-wide
// (same rationale as `build_encrypted_envelope_actor` above).
#[allow(clippy::redundant_pub_crate)]
pub(crate) async fn send_checkpoint(
    deps: &ActorDeps,
    cell: &mut crate::context::actor::class_s::ClassSCell,
    context_id: &str,
    sender_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
    checkpoint: &scp_event_log::checkpoint::ConsistencyCheckpoint,
) -> Result<(), ContextError> {
    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): this is now a plain `async fn` taking
    // `&mut ClassSCell` — `&mut PerContextState` is `Send`, so the crypto view can
    // be held across the fan-out await and the former sync-prelude gymnastics (a
    // `&PerContextState`-shared prelude producing owned routing data because
    // `&PerContextState` is `!Send`) are gone.
    //
    // Routing (shared reads via `cell` `Deref`) into OWNED data, parallel to the
    // application-data send path (§9.10.4): broadcast contexts address the
    // derivable broadcast RID; encrypted contexts fan out to each known peer
    // pseudonym. An empty encrypted routing set is a legitimate no-op.
    let (recipients_data, routing_ids) = if cell.broadcast_context.is_some() {
        (
            std::collections::HashMap::new(),
            vec![scp_protocol::context::broadcast_routing_id(context_id)],
        )
    } else {
        let peer_pseudonyms: Vec<[u8; 32]> = cell
            .routing
            .peer_registry()
            .map(|reg| reg.values().copied().collect())
            .unwrap_or_default();
        (
            cell.access.access_key_store.get_all(context_id),
            peer_pseudonyms,
        )
    };

    let message = CheckpointMessage {
        tag: CHECKPOINT_PAYLOAD_TAG.to_owned(),
        checkpoint: checkpoint.clone(),
    };
    let payload = rmp_serde::to_vec_named(&message).map_err(|e| {
        ContextError::CryptoFailed(format!("checkpoint message serialization: {e}"))
    })?;

    // Seal through the actor's field-granular Class-C `&mut ContextCryptoState`.
    let mut view = cell.class_c_view();
    let Some(crypto_state) = view.mode_mut().crypto_mut() else {
        // Broadcast context: no MLS `ContextCryptoState` to seal with. This is
        // DELIVERY-IDENTICAL to the pre-PR-7 provider path (which errored "no MLS
        // group" and was swallowed best-effort → nothing delivered); we simply
        // drop the spurious warn. Whether broadcast-context checkpoints SHOULD
        // deliver via MLS is a pre-existing gap — broadcast checkpoint
        // MLS-delivery: tracked as a separate §9.9.3 finding (a broadcast-native
        // redesign, outside this ownership move).
        return Ok(());
    };
    encrypt_and_send(
        deps,
        Some(crypto_state),
        None,
        // Consistency checkpoints are device/human-originated signals, not
        // agent-autonomous messages — sign under `#active` (ADR-039).
        MessageSigner::Active(signing_key),
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
    .await
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
// ADR-049 PR-7 (inquisitor item 8): narrowed `pub` → `pub(crate)`. Same rationale
// as `send_checkpoint` above — the only callers of this FREE function are in-crate
// actor handlers (`handle_send_heartbeat`); cross-crate code reaches heartbeat
// sending through the distinct `Supervisor::send_heartbeat` method. `pub(crate)`
// is the minimal correct visibility and keeps the seam out of the source-text
// `check-cross-layer` gate with no PR-body exemption. `redundant_pub_crate` is a
// false positive (the enclosing module is already `pub(crate)`, the item is
// reached crate-wide).
#[allow(clippy::redundant_pub_crate)]
pub(crate) async fn send_heartbeat(
    deps: &ActorDeps,
    cell: &mut crate::context::actor::class_s::ClassSCell,
    context_id: &str,
    sender_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<(), ContextError> {
    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): plain `async fn` taking `&mut ClassSCell`
    // (Send), so the seal runs on the actor's crypto view held across the fan-out
    // await — the former sync-prelude (needed only because `&PerContextState` is
    // `!Send`) is gone.
    //
    // Send-authorization gates, mirroring `send_message` (§9.9.2 routes a
    // heartbeat through the same write path, so it must clear the same write
    // gates). Without these a member whose `MessagesWrite` capability was
    // suspended or revoked could keep asserting liveness on the write path, and a
    // heartbeat racing a context close could slip through after the context is no
    // longer active. Shared reads via `cell` `Deref`.
    state::require_active(&cell.handle)?;
    if cell.broadcast_context.is_none()
        && !cell
            .role_state
            .member_has_capability(sender_did.as_ref(), &Capability::MessagesWrite)
    {
        let is_suspended = cell
            .role_state
            .suspended_for(sender_did.as_ref())
            .is_some_and(|s| s.contains(&Capability::MessagesWrite));
        let msg = if is_suspended {
            format!("member {sender_did} write access has been revoked")
        } else {
            format!("member {sender_did} does not have messages:write capability")
        };
        return Err(ContextError::PermissionDenied(msg));
    }

    // Routing parallels the application-data and checkpoint send paths (§9.10.4):
    // broadcast contexts address the derivable broadcast RID; encrypted contexts
    // fan out to each known peer pseudonym. An empty encrypted routing set is a
    // legitimate no-op.
    let (recipients_data, routing_ids) = if cell.broadcast_context.is_some() {
        (
            std::collections::HashMap::new(),
            vec![scp_protocol::context::broadcast_routing_id(context_id)],
        )
    } else {
        let peer_pseudonyms: Vec<[u8; 32]> = cell
            .routing
            .peer_registry()
            .map(|reg| reg.values().copied().collect())
            .unwrap_or_default();
        (
            cell.access.access_key_store.get_all(context_id),
            peer_pseudonyms,
        )
    };

    // Seal through the actor's field-granular Class-C `&mut ContextCryptoState`.
    let mut view = cell.class_c_view();
    let Some(crypto_state) = view.mode_mut().crypto_mut() else {
        // Broadcast context: no MLS `ContextCryptoState`. Delivery-identical no-op
        // (see `send_checkpoint`). Broadcast checkpoint MLS-delivery: tracked as a
        // separate §9.9.3 finding.
        return Ok(());
    };
    encrypt_and_send(
        deps,
        Some(crypto_state),
        None,
        // Heartbeats are device/human-originated liveness beacons, not
        // agent-autonomous messages — sign under `#active` (ADR-039).
        MessageSigner::Active(signing_key),
        context_id,
        sender_did,
        // Heartbeats carry NO user content — the empty payload is the whole point:
        // a minimal liveness beacon, padded by the envelope machinery.
        &[],
        &recipients_data,
        // Heartbeats do not consume the application content sequence; the receive
        // path classifies them before the sequence tracker.
        0,
        None,
        &routing_ids,
        MessageType::Heartbeat,
    )
    .await
}

// ---------------------------------------------------------------------------
// 10. authorize_send_payment_prepare
// ---------------------------------------------------------------------------

/// Authorizes escrow for send payment (Phase 1.5 of [`send_message`]).
/// Sync PREPARE half of the send-path payment authorization (ADR-049 §9): reads
/// the SHARED `&PerContextState` (via `&*cell`) to evaluate whether a non-zero
/// cost applies and, if so, returns the OWNED, `Send` inputs the async escrow
/// hold needs. Returns `None` when no adapter / no policy / zero cost
/// short-circuits authorization.
///
/// The split exists so the cell borrow drops at the call boundary (the result is
/// owned), leaving the cell free for the `send_message` body's subsequent
/// `.await` of [`crate::context::economy_helpers::authorize_paid_action_hold`] —
/// a `&ClassSCell` held ACROSS that await would make the actor future non-`Send`
/// (`ClassSCell` is not `Sync`).
pub fn authorize_send_payment_prepare(
    cell: &crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    sender_did: &DID,
) -> Option<crate::context::economy_helpers::OwnedAuthInputs> {
    crate::context::economy_helpers::authorize_paid_action_prepare(
        cell,
        deps,
        scp_protocol::economy::types::PaidActionType::MessageSend,
        sender_did,
    )
}

// ---------------------------------------------------------------------------
// 11. capture_send_payment
// ---------------------------------------------------------------------------

/// Captures the escrow hold after a successful send (Phase 3 of
/// [`send_message`]). Best-effort: capture failure is logged + audited
/// but does NOT roll back budget (H8). On failure a
/// `PaymentCaptureFailed` event is appended (H19).
pub async fn capture_send_payment(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    auth: Option<crate::context::economy_logic::PaidActionAuthorization>,
    sender_did: &DID,
    context_id: &str,
    deducted_cost: Option<scp_protocol::economy::types::Amount>,
) {
    let Some(a) = auth else {
        return;
    };
    // Capture splits the provider-driven async half (`capture_and_verify_paid_action`,
    // NO state borrow — awaited with the cell free) from the field-narrowed sync
    // surfacing (`surface_paid_action_receipt`, supplied the two Class-C fields
    // from a non-persisting `ClassCMut` view). The coalesced persist is driven by
    // the actor run loop on `Outcome::ok_mutated`.
    match crate::context::economy_helpers::capture_and_verify_paid_action(a).await {
        Ok(Some(receipt)) => {
            let mut view = cell.class_c_view();
            // The two disjoint Class-C `&mut` fields are taken SEQUENTIALLY through
            // the view inside `surface_paid_action_receipt`'s own field-narrowed
            // sub-calls; pass them one at a time so no two view accessors overlap.
            crate::context::economy_helpers::emit_payment_received_event(
                view.receive_buffer_mut(),
                deps,
                &receipt,
                context_id,
            );
            crate::context::economy_helpers::record_payment_receipt(
                view.payment_receipts_mut(),
                &receipt,
            );
        }
        Ok(None) => {}
        Err(e) => {
            // H8: do NOT rollback budget — service was delivered.
            tracing::warn!(
                context_id,
                "payment capture failed after successful send: {e}"
            );
            // H19: surface the capture failure as a local `ContextEvent` (no durable
            // Merkle leaf — per-payee, non-convergent; ADR-051 §6 / phase-2.md §2).
            record_payment_capture_failure(
                cell.class_c_view().receive_buffer_mut(),
                deps,
                context_id,
                "send_message",
                sender_did,
                &e.to_string(),
                deducted_cost,
            );
        }
    }
}

/// Surface a `PaymentCaptureFailed` as a local `ContextEvent` (receive-buffer
/// push + `event_tx` notification). Actor-shape inline replacement for
/// `manager_methods::record_payment_capture_failure`.
///
/// Per ADR-051 §6 / the phase-2.md ADR-011 amendment exclusion taxonomy §2, the
/// payment receipts (`PaymentReceived` / `PaymentCaptureFailed`) are per-payee,
/// non-convergent events appended by their payee alone — they are excluded from
/// the canonical Merkle log so two honest members derive the same
/// `event_log_merkle_root` (§9.9.3). The former durable
/// `EventType::PaymentCaptureFailed` append (and its `checkpoint_events_since`
/// increment) is removed; the `ContextEvent::PaymentCaptureFailed` emission
/// below is the sole surfacing of a capture failure.
#[allow(clippy::too_many_arguments)]
fn record_payment_capture_failure(
    receive_buffer: &mut scp_protocol::context::membership::ReceiveBuffer,
    deps: &ActorDeps,
    context_id: &str,
    action: &str,
    actor_did: &DID,
    error_msg: &str,
    cost: Option<scp_protocol::economy::types::Amount>,
) {
    let event = ContextEvent::PaymentCaptureFailed {
        action: action.to_owned(),
        actor_did: actor_did.clone(),
        error: error_msg.to_owned(),
        cost: cost.map(scp_protocol::economy::types::Amount::value),
    };
    emit_event_into(receive_buffer, event, context_id, deps.event_tx.as_ref());
}

// ---------------------------------------------------------------------------
// 12. finalize_send
// ---------------------------------------------------------------------------

/// Computes and caches the sender's participation record after a send.
/// Factored out of [`finalize_send`] to keep that function within the line
/// budget; pure bookkeeping with no error path (a missing Merkle root or a
/// zero-count record is simply not cached).
fn record_send_participation(
    view: &mut ClassCMut,
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
            // attestation_count is a credential-layer, verifier-relative fact
            // (§7.3.2); this messaging path gates only on participation_count and
            // has no attestation-cache access, so it passes an empty accessible-
            // attestation set (count 0) by design — NOT a stub.
            &[],
        )
        && record.participation_count > 0
    {
        view.governance_class_c_mut()
            .participation_cache_mut()
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
/// `token` carries the ADR-049 §9 deferred-persist obligation for this send
/// (BLACK-001): it is `Some` when a paid send burned a spending-UCAN nonce in
/// Phase 1 (`enforce_send_economy` mutated the actor-owned
/// `spending_nonce_tracker`, Class S monotonic state that does NOT survive an
/// actor crash), and `None` for a free / non-spending send. When `Some`, the
/// final persist is the token's FAIL-CLOSED `commit`: a persist failure returns
/// [`ContextError::PersistenceFailed`] so the paid send is NOT acknowledged
/// while its nonce-consume is unpersisted, exactly mirroring the outlet-invoke
/// path in `reserve_outlet_economy`. When `None`, the persist stays best-effort
/// (Class C) — the common path is not regressed. The token is consumed on EVERY
/// path `finalize_send` can take (the TTL-expiry arm commits it too — a late TTL
/// expiry must still persist the burned nonce, keep-direction).
///
/// # Sequence-rollback ownership (ADR-049 §9, round-9 leak fix)
///
/// `finalize_send` OWNS the per-sender sequence rollback on ALL of its error
/// exits — the TTL early-return below and the final persist failure (in
/// [`persist_finalized_send`]). (The former FIRST `MessageSent` durable-append
/// rollback site is gone: per ADR-051 §6 / the phase-2.md ADR-011 amendment
/// exclusion taxonomy §2, `MessageSent` is a per-author, non-convergent event
/// excluded from the canonical Merkle log — there is no durable append to fail,
/// so the local `ContextEvent::MessageSent` emission below is now the sole
/// surfacing of a send.) The
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
pub async fn finalize_send(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    sender_did: &DID,
    sequence: u64,
    payload: &[u8],
    signing_key: Option<&ed25519_dalek::SigningKey>,
    token: Option<crate::context::actor::class_s::ClassSCommitToken>,
    is_broadcast: bool,
) -> Result<(), ContextError> {
    // M12: `MessageSent` is no longer a durable Merkle leaf — per ADR-051 §6 /
    // the phase-2.md ADR-011 amendment exclusion taxonomy §2 it is a per-author,
    // non-convergent event surfaced only as the local `ContextEvent::MessageSent`
    // emitted below. The former pre-consequence durable append (and its
    // sequence-rollback-on-append-failure) is removed so two honest members
    // derive the same `event_log_merkle_root` (§9.9.3).

    // Phase 3 reacquire-and-mutate is unnecessary in the actor model;
    // the actor owns state for the duration of the command. We DO
    // re-check the lifecycle state — a TTL expiry could land between
    // Phase 1 and finalize within the same command if the actor's TTL
    // arm fires (Phase 2A.9 wires this). For Phase 2A.7 this matches
    // the legacy contract: rollback the sequence number and exit. The
    // handle read goes through the Class-C view (its borrow ends before the
    // shared-`&` token commit below).
    if state::require_active(cell.class_c_view().handle_mut()).is_err() {
        // Only encrypted sends reserved a sequence (broadcast publishes carry 0
        // and never call `next_sequence_number`) — broadcast must not roll back.
        if !is_broadcast {
            cell.class_c_view()
                .membership_class_c_mut()
                .rollback_sequence_number(sender_did);
        }
        // A spending-UCAN nonce burned in Phase 1 stays CONSUMED (a late TTL
        // expiry must not freshen it); commit its deferred token so it persists
        // fail-closed — a crash before coalesce cannot roll the consume back
        // (ADR-049 §9 Class S, keep-direction). A free send carries no token. The
        // token's `commit` takes a SHARED `&PerContextState` (via `&*cell`).
        if let Some(t) = token {
            t.commit(cell, deps, context_id).await?;
        }
        return Ok(());
    }

    let now = deps.clock.now_secs();
    // ADR-049 §9 (RED-CS3): `true` when consequence enforcement performs a
    // downward-authorization mutation (a capability suspension or an `AssignRole`
    // demotion), so the final persist is upgraded to fail-closed (keep-direction)
    // — a coalesce-window crash must not lose the mutation. Bound from the view
    // block below so the value is set exactly once, then folded into a token
    // obligation (free branch only) at the persist site.
    // The GROW methods arm this sink directly when a downward-auth mutation is
    // applied (GAP-A: arming is coupled to the mutation, not a separate call). It
    // is owned here at the cell boundary and reconciled with the send's nonce
    // `token` below.
    let mut downward_auth_sink: Option<crate::context::actor::class_s::ClassSCommitToken> = None;
    // Class-C field mutations run through the non-persisting view (coalesced —
    // the run loop persists on `mutated`); the view borrow ends (NLL) before the
    // cell-taking checkpoint-broadcast + fail-closed persist below.
    {
        let mut view = cell.class_c_view();
        let sent_event = ContextEvent::MessageSent {
            sender_did: sender_did.clone(),
            sequence_number: sequence,
            payload: payload.to_vec(),
        };
        emit_event_into(
            view.receive_buffer_mut(),
            sent_event,
            context_id,
            deps.event_tx.as_ref(),
        );

        // Consequence enforcement.
        let (send_events, convergent_now) =
            crate::context::governance_logic::event_log_entries_for_consequences(
                view.receive_buffer_mut(),
                context_id,
                now,
                &*deps.event_log,
            );
        let consequence_rules: Vec<ConsequenceRule> = view
            .governance_class_c_mut()
            .consequence_rules_mut()
            .clone();
        let send_triggered = evaluate_consequence_rules(
            &consequence_rules,
            &send_events,
            sender_did.as_ref(),
            now,
            convergent_now,
        );
        {
            let mut split = view.consequence_split();
            // ADR-049 §9 (RED-CS3): a downward-auth mutation (a
            // `suspended_capabilities` GROW or an `AssignRole` `member_capabilities`
            // replacement) ARMS `downward_auth_sink` via the GROW method itself.
            // When armed, the final persist below is upgraded to fail-closed so the
            // mutation is durable before this send acks.
            let _ = crate::context::governance_logic::enforce_triggered_consequences(
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
                &mut downward_auth_sink,
            )
            .await;
        }

        // Participation record (#1530).
        record_send_participation(
            &mut view,
            deps,
            context_id,
            context_id_bytes,
            sender_did,
            &send_events,
            now,
        );

        // Checkpoint tracking (§9.9.3).
        *view.checkpoint_events_since_mut() += 1;
    }
    create_and_broadcast_checkpoint_if_due(cell, deps, context_id, sender_did, signing_key, now)
        .await;

    // Reconcile the GROW-armed `downward_auth_sink` with the send's nonce `token`
    // so EXACTLY ONE fail-closed persist is owed on every branch (ADR-049 §9,
    // RED-CS3):
    // - FREE branch (`token.is_none()`): the armed sink token IS the obligation —
    //   pass it straight through.
    // - PAID branch (`token.is_some()`): the nonce `token` already owes a
    //   fail-closed `commit` that covers the same GROW (one persist makes the whole
    //   in-memory state durable). An armed sink token here is genuinely REDUNDANT;
    //   it is subsumed by the nonce token (consuming it without a second persist).
    let downward_auth_obligation = match (downward_auth_sink, token.is_some()) {
        (Some(sink_token), false) => Some(sink_token),
        (Some(sink_token), true) => {
            // The nonce token's commit covers this GROW — subsume the redundant one.
            sink_token.subsume(context_id);
            None
        }
        (None, _) => None,
    };

    persist_finalized_send(
        cell,
        deps,
        context_id,
        sender_did,
        token,
        is_broadcast,
        downward_auth_obligation,
    )
    .await
}

/// Creates a consistency checkpoint when due (§9.9.3 thresholds) and, when one
/// is produced, broadcasts it to peers via [`send_checkpoint`] so they can
/// detect relay equivocation (§23.7).
///
/// Factored out of [`finalize_send`] to keep that function within the clippy
/// line budget. The local retention (pushing into the view's `checkpoints`)
/// happens inside `create_checkpoint_if_due_view`; the broadcast is
/// **best-effort** — a
/// transport failure is logged but never rolls back the just-completed
/// application send, because the checkpoint is an independent
/// consistency-monitoring artifact, not part of the message's delivery
/// guarantee. A missing signing key (e.g. a context with no local custody)
/// skips checkpoint creation entirely.
async fn create_and_broadcast_checkpoint_if_due(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    sender_did: &DID,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    now: u64,
) {
    let Some(sk) = signing_key else {
        return;
    };
    // Build + retain the checkpoint through the non-persisting Class-C view
    // (coalesced — the run loop persists on `mutated`). The `&mut view` borrow
    // ends before the shared-`&` `send_checkpoint` read below (NLL).
    let due_checkpoint = {
        let mut view = cell.class_c_view();
        let broadcast_context_is_none = view.broadcast_class_c_mut().is_none();
        let mls_epoch = view.epoch_mut().mls_epoch;
        crate::context::queries_helpers::create_checkpoint_if_due_view(
            &mut view,
            context_id,
            broadcast_context_is_none,
            mls_epoch,
            sender_did,
            sk,
            now,
            &*deps.event_log,
        )
    };
    // ADR-049 PR-7: `send_checkpoint` now takes `&mut ClassSCell` (Send) and seals
    // on the actor crypto view; `cell` is free here (the `due_checkpoint` view
    // borrow above ended) and this is its last use.
    if let Some(checkpoint) = due_checkpoint
        && let Err(e) = send_checkpoint(deps, cell, context_id, sender_did, sk, &checkpoint).await
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
///
/// `downward_auth_obligation` (ADR-049 §9, RED-CS3): a fail-closed-persist token
/// minted ONLY on the FREE-send branch when this send's consequence enforcement
/// performed a downward-authorization mutation (a `suspended_capabilities` GROW or
/// an `AssignRole` `member_capabilities` replacement). On the PAID branch the
/// downward-auth mutation rides the nonce `token`'s own fail-closed `commit` (one
/// persist covers all in-memory state), so `finalize_send` mints no separate
/// obligation there and this is `None`. The free path commits this token to upgrade
/// from best-effort to fail-closed so a coalesce-window crash cannot silently
/// re-grant removed authority. The token carrier (vs. the prior `bool`) makes a
/// populated-but-undischarged obligation a Drop-guard PANIC in debug/CI.
async fn persist_finalized_send(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    sender_did: &DID,
    token: Option<crate::context::actor::class_s::ClassSCommitToken>,
    is_broadcast: bool,
    downward_auth_obligation: Option<crate::context::actor::class_s::ClassSCommitToken>,
) -> Result<(), ContextError> {
    match token {
        // Paid send: commit the deferred nonce token — its `commit` performs the
        // fail-closed persist (ADR-049 §9 Class S, keep-direction) of ALL in-memory
        // state, so a downward-auth mutation applied on this send is already covered
        // (no separate obligation is minted on this branch, so
        // `downward_auth_obligation` is `None` here). The token's `commit` takes a
        // SHARED `&PerContextState` (via `&*cell`). On failure roll the reserved
        // sequence back through the Class-C view (this fn owns that rollback; the
        // caller does not double-revert) and surface the error.
        Some(t) => {
            debug_assert!(
                downward_auth_obligation.is_none(),
                "paid send mints no separate downward-auth obligation — the nonce \
                 token's commit covers the GROW",
            );
            if let Err(e) = t.commit(cell, deps, context_id).await {
                if !is_broadcast {
                    cell.class_c_view()
                        .membership_class_c_mut()
                        .rollback_sequence_number(sender_did);
                }
                return Err(e);
            }
        }
        // Free / non-spending send: best-effort persist (Class C — not regressed)
        // UNLESS this send applied a downward-auth mutation (a capability
        // suspension or an `AssignRole` demotion), in which case the downward-auth
        // obligation's token commits fail-closed (ADR-049 §9, keep-direction).
        None => {
            if let Some(obligation) = downward_auth_obligation {
                obligation.commit(cell, deps, context_id).await?;
            } else {
                persist_state_best_effort(cell, deps, context_id).await;
            }
        }
    }
    Ok(())
}

/// Build the snapshot for `context_id` from owned actor state, threading in
/// the supervisor-owned MLS crypto state. Shared by the best-effort and
/// fail-closed persist paths. A crypto-export failure marks the snapshot
/// `needs_reconnect` (so restore fires the §23.11 reconnection pipeline)
/// rather than failing — the crypto state is Class M (crash-surviving), so a
/// transient export failure does not lose security state.
///
/// `pub(crate)` so the `ClassSCommitToken` deferred-persist terminals
/// (`commit` / `discharge_with`) can build the owned snapshot in their OWN
/// frame and drop the `&PerContextState` borrow BEFORE awaiting
/// [`persist_snapshot_fail_closed`]. `PerContextState` is `!Sync` (it holds a
/// `dyn FnMut` sink), so a `&PerContextState` held across an `.await` makes the
/// actor future `!Send` and fails `tokio::spawn`. Building the snapshot first
/// keeps the borrow off the await point (ADR-049 Decision 7).
pub fn build_snapshot_for_persist(
    state: &PerContextState,
    deps: &ActorDeps,
    context_id: &str,
) -> crate::context::state::ContextSnapshot {
    let mut snapshot = build_snapshot_from_state(state);
    // ADR-056: canonical digest, not a re-hash of the hex id.
    let ctx_id_bytes = state::context_id_to_bytes(context_id);
    // ADR-049 PR-6 (read-authority switch): the per-sender epoch + recv-sequence
    // floors are sourced from the AUTHORITATIVE Supervisor-owned Class-M registry
    // (`deps.supervisor.export_*`) and threaded into `export_crypto_state` as the
    // durable-blob params. ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the export now runs
    // on the actor's `state` (was the provider); the X25519 wrapping keypair enters
    // as params from the retained `deps.crypto.wrapping_keypair()`, and the send
    // sequence is read from `state.send_tracker` inside the twin.
    let (wrapping_public_key, wrapping_secret_key) = deps.crypto.wrapping_keypair();
    match state.export_crypto_state(
        deps.supervisor.export_sender_key_epochs(&ctx_id_bytes),
        deps.supervisor.export_recv_sequence_floors(&ctx_id_bytes),
        wrapping_public_key,
        &*wrapping_secret_key,
    ) {
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

/// Whether an MLS crypto export is durable enough to stand up a Welcome-JOINER.
///
/// [`build_snapshot_for_persist`] is deliberately FAIL-OPEN for existing
/// members: on an `export_crypto_state` failure it writes an EMPTY crypto blob
/// with `needs_reconnect = true` and the persist SUCCEEDS, so restore re-enters
/// the §23.11 reconnection pipeline. A Welcome-JOINER cannot reconnect-derive
/// (it would need a fresh Welcome), so for the spawn-from-Welcome entrypoint an
/// empty / errored crypto export is FATAL — a keyless snapshot there means a
/// live send-capable actor with no durable keys.
///
/// The persisted snapshot's crypto blob is a 1:1 copy of the
/// `export_crypto_state` result, so re-reading the live export tells the
/// entrypoint exactly what the snapshot carries WITHOUT depending on the
/// persistence backend supporting read-back (the default `NoopContextPersistence`
/// and the `for_query_shim` path do not). Returns `true` only when the export
/// succeeded AND carries a non-empty blob.
///
/// The sole caller is `Supervisor::spawn_actor_from_welcome` (test-only until
/// the FFI follow-on slice wires a production consumer), hence `dead_code`.
#[must_use]
#[allow(dead_code)]
pub const fn welcome_snapshot_crypto_is_durable(export: &Result<Vec<u8>, ContextError>) -> bool {
    matches!(export, Ok(blob) if !blob.is_empty())
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
///
/// # Not `async fn` — `Send` discipline (ADR-049 Decision 7)
///
/// This is a SYNC fn returning a future, NOT an `async fn`. The
/// `&PerContextState` is consumed by [`build_snapshot_for_persist`] in the
/// synchronous prelude and is NOT captured by the returned future (which holds
/// only the owned snapshot + `deps` / `context_id`). `PerContextState` is
/// `!Sync` (it holds a `dyn FnMut` sink), so an `async fn` — which keeps its
/// `&PerContextState` parameter in the future for the whole future lifetime —
/// would make every awaiting actor handler `!Send` and fail `tokio::spawn`.
/// `use<'d, 'c>` precisely captures only the `deps` / `context_id` lifetimes
/// (edition 2024), excluding the `state` borrow.
pub fn persist_state_best_effort<'d, 'c>(
    state: &PerContextState,
    deps: &'d ActorDeps,
    context_id: &'c str,
) -> impl std::future::Future<Output = ()> + Send + use<'d, 'c> {
    let snapshot = build_snapshot_for_persist(state, deps, context_id);
    async move {
        if let Err(e) = deps
            .persistence
            .persist_context(context_id, &snapshot)
            .await
        {
            crate::metrics::record_persistence_failure();
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to persist context snapshot"
            );
        }
    }
}

/// Fail-closed persist of the current actor state (ADR-049 §9 Class S).
///
/// Persists and, on failure, returns
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
/// # Not `async fn` — `Send` discipline (ADR-049 Decision 7)
///
/// SYNC fn returning a future (see [`persist_state_best_effort`] for the full
/// rationale): the `&PerContextState` is consumed in the synchronous prelude and
/// is NOT captured by the returned future, so every awaiting actor handler stays
/// `Send`.
pub fn persist_state_fail_closed<'d, 'c>(
    state: &PerContextState,
    deps: &'d ActorDeps,
    context_id: &'c str,
) -> impl std::future::Future<Output = Result<(), ContextError>> + Send + use<'d, 'c> {
    // Build the owned snapshot FIRST so the `&PerContextState` borrow is dropped
    // before the returned future — keeps this future `Send` (see
    // [`build_snapshot_for_persist`]).
    let snapshot = build_snapshot_for_persist(state, deps, context_id);
    async move { persist_snapshot_fail_closed(&snapshot, deps, context_id).await }
}

/// Fail-closed persist of an ALREADY-BUILT snapshot (ADR-049 §9 Class S).
///
/// The `&PerContextState`-holding half of [`persist_state_fail_closed`] split
/// out so the `ClassSCommitToken` deferred-persist terminals can build the
/// snapshot in their own frame (dropping the `!Send` `&PerContextState` borrow)
/// and then await this owned-`&ContextSnapshot` persist. `ContextSnapshot` is
/// `Send`, so a caller holding `&snapshot` across the await stays `Send`.
///
/// Records the failure metric and logs on error, identically to
/// [`persist_state_fail_closed`].
///
/// # Errors
///
/// Returns [`ContextError::PersistenceFailed`] if the underlying
/// `persist_context` write fails.
pub async fn persist_snapshot_fail_closed(
    snapshot: &crate::context::state::ContextSnapshot,
    deps: &ActorDeps,
    context_id: &str,
) -> Result<(), ContextError> {
    deps.persistence
        .persist_context(context_id, snapshot)
        .await
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
        approved_proposals: _approved_proposals,
        next_proposal_seq: _next_proposal_seq,
        freeze: _freeze,
        pending_ceiling_modification: _pending_ceiling_modification,
        pending_economic_policy_change: _pending_economic_policy_change,
        registered_outlets: _registered_outlets,
        outlet_interfaces: _outlet_interfaces,
        pruning_policy: _pruning_policy,
        economic_policy: _economic_policy,
        budget_tracker: _budget_tracker,
        consequence_rules: _consequence_rules,
        velocity_tracker: _velocity_tracker,
        participation_cache: _participation_cache,
        cooldown_until: _cooldown_until,
        message_pricing: _message_pricing,
        hard_rate_limit: _hard_rate_limit,
        revoked_spending_ucan_cids: _revoked_spending_ucan_cids,
        proposal_timestamps: _proposal_timestamps,
        // Class-S governance subset (ADR-049 §9): exhaustively destructured so a
        // NEW Class-S governance field forces a conscious persist decision here
        // too. `executed_proposals` / `threshold_signers` / `threshold_value` /
        // `spending_nonce_tracker` are all persisted into the snapshot below.
        class_s:
            crate::context::state::GovernanceClassS {
                executed_proposals: _executed_proposals,
                threshold_signers: _threshold_signers,
                threshold_value: _threshold_value,
                spending_nonce_tracker: _spending_nonce_tracker,
            },
        // --- Transient: deliberately NOT persisted (rebuilt at restore). ---
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

    let context_state_value = state.handle.state();
    // Persist the ABSOLUTE convergent deadline verbatim (ADR-049 §9): restore/
    // import re-arm the SAME instant, so a create-window `None` re-derives from
    // `creation + ttl` and a prior extension is not recomputed away (D1/D2).
    let ttl_deadline_secs = state.ttl.timer.deadline_unix_secs;
    let grace_entries = state.epoch.grace_store.to_grace_entries();

    crate::context::state::ContextSnapshot {
        context_id: state.handle.context_id().to_owned(),
        creation_timestamp_secs: state.creation_timestamp_secs,
        state: context_state_value,
        context_params: state.handle.params().clone(),
        membership: state.membership.clone(),
        role_state: state.role_state.clone(),
        event_log_merkle_root: [0u8; 32],
        executed_proposals: state
            .governance
            .class_s
            .executed_proposals
            .keys()
            .copied()
            .collect(),
        ttl_deadline_secs,
        registered_outlets: state.governance.registered_outlets.clone(),
        read_exclusion_list: state.access.read_exclusion_list.clone(),
        outlet_interfaces: state.governance.outlet_interfaces.clone(),
        threshold_signers: state.governance.class_s.threshold_signers.clone(),
        threshold_value: state.governance.class_s.threshold_value,
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
        spending_nonce_tracker_state: state
            .governance
            .class_s
            .spending_nonce_tracker
            .snapshot_entries(),
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
        xctx_committed_stream_outputs: xctx_committed_stream_outputs_snapshot(state),
        xctx_committed_invocations: xctx_committed_invocations_snapshot(state),
        // ADR-049 §9 Class S (spec §6.2.4): persist the caller-side durable
        // reservation reversal records so a `PreparingB`-window crash can reverse
        // the caller deduction + void the escrow without the in-memory carrier.
        xctx_caller_reservations: xctx_caller_reservations_snapshot(state),
        xctx_nonce_dedup: xctx_nonce_dedup_snapshot(state),
        // §7.3.8 Class S: persist the value-caveat counters so a consumed
        // `max_calls` / `amount_max_cumulative` / `rate_window` cap survives an
        // actor crash rather than un-consuming. See [`caveat_counters_snapshot`].
        caveat_counters: caveat_counters_snapshot(state),
        // Fix-D Class S: persist the streaming reservation recovery records so a
        // crash-restore can RELEASE the escrow hold + cumulative counter reserve
        // of any stream whose off-mailbox pump survived the crash. See
        // [`stream_reservations_snapshot`].
        stream_reservations: stream_reservations_snapshot(state),
        // ADR-049 §9 Class S (§5.14.8 block-before-serve): fold the broadcast
        // security + roster state (per-author key epochs, block lists, subscriber
        // registry) into the fail-closed snapshot so a block / governance ban /
        // key-epoch advance is durable BEFORE the operation acks. `None` for
        // non-broadcast contexts.
        broadcast: state
            .broadcast_context
            .as_ref()
            .map(scp_protocol::context::broadcast::BroadcastContext::to_snapshot),
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
        .class_s
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
/// cross-context outlet-invocation captures (spec §6.2.4 "Exactly-once
/// execution with durable output capture"; ADR-049 §9). The live
/// [`CommittedOutletInvocation`](crate::context::supervisor::saga_prepared_state::CommittedOutletInvocation)
/// carries no §9.4.3 bearer bytes (public receipt + output), so — unlike
/// [`saga_pending_snapshot`] — the snapshot stores it directly via `Clone`.
/// Used at every snapshot builder so a crash between Commit-B capture and the
/// next coalesced write cannot lose the durable output (which would re-invoke
/// the outlet on replay).
pub(in crate::context) fn xctx_committed_outputs_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<
    crate::context::supervisor::saga_journal::SagaId,
    crate::context::supervisor::saga_prepared_state::CommittedOutletInvocation,
> {
    state.class_s.xctx_committed_outputs.clone()
}

/// Build the Class-S snapshot projection of the actor's COMMITTED cross-context
/// **streaming** outlet-invocation captures (ADR-061 seal phase; spec §6.2.5
/// streaming saga; ADR-049 §9). The streaming sibling of
/// [`xctx_committed_outputs_snapshot`]. The live
/// [`CommittedStreamingOutletInvocation`](crate::context::supervisor::saga_prepared_state::CommittedStreamingOutletInvocation)
/// carries no §9.4.3 bearer bytes (public receipt + sealed root), so the snapshot
/// stores it directly via `Clone`. Used at every snapshot builder so a crash
/// between the seal-close capture and the next coalesced write cannot lose the
/// durable witness (which would re-invoke the outlet on replay).
pub(in crate::context) fn xctx_committed_stream_outputs_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<
    crate::context::supervisor::saga_journal::SagaId,
    crate::context::supervisor::saga_prepared_state::CommittedStreamingOutletInvocation,
> {
    state.class_s.xctx_committed_stream_outputs.clone()
}

/// Build the Class-S snapshot projection of the actor's caller-side (A-owned)
/// COMMITTED cross-context outlet-invocation witness set (spec §6.2.4 "Commit",
/// caller side; §17.16.4 crash recovery; ADR-049 §9). The live
/// [`ClassSState::xctx_committed_invocations`](crate::context::actor::state::ClassSState::xctx_committed_invocations)
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
    state.class_s.xctx_committed_invocations.clone()
}

/// Build the Class-S snapshot projection of the actor's caller-side durable
/// reservation reversal records (spec §6.2.4 "Reservation release on every
/// terminal path"; §17.16.4 crash recovery; ADR-049 §9). The live
/// [`ClassSState::xctx_caller_reservations`](crate::context::actor::state::ClassSState::xctx_caller_reservations)
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
    state.class_s.xctx_caller_reservations.clone()
}

/// Build the Class-S snapshot projection of the actor's B-owned cross-context
/// nonce-dedup cache (spec §6.2.4 "Freshness / anti-replay"; ADR-049 §9). The
/// live [`NonceDedup`](scp_protocol::crypto::sender_keys::NonceDedup) projects
/// to a plain `{nonce → first-seen secs}` map via `entries()`. Persisting it at
/// every snapshot builder makes the replay-protection cache CRASH-SURVIVING: a
/// restart no longer reopens the 5-minute window for a fresh-`SagaId` replay of
/// a `CrossContextOutletInvoke` (BLACK-624-01). Same-node restore rehydrates it;
/// cross-node export/import drops it to empty (B's freshness state has no
/// authority on a foreign node).
pub(in crate::context) fn xctx_nonce_dedup_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<[u8; 16], u64> {
    state.class_s.xctx_nonce_dedup.entries()
}

/// Build the Class-S snapshot projection of the actor's §7.3.8 value-caveat
/// counters (ADR-049 §9). The live
/// [`CaveatCounters`](crate::trust::caveat_counters::CaveatCounters) is a plain
/// `Clone` serde value, so — like `xctx_committed_invocations_snapshot` — the
/// snapshot stores the map directly. Exists so EVERY snapshot builder projects
/// this Class-S field through ONE helper, exactly like its siblings — no Class-S
/// field is centralized by convention alone. Without persisting it, a crash that
/// rolled a consumed cap back behind an acked invocation would re-open the
/// spend/rate window the counter closes.
pub(in crate::context) fn caveat_counters_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<String, crate::trust::caveat_counters::CaveatCounters> {
    state.class_s.caveat_counters.clone()
}

/// Project [`ClassSState::stream_reservations`](crate::context::actor::state::ClassSState::stream_reservations)
/// onto its snapshot map (Fix-D). The live
/// [`StreamReservationRecord`](crate::context::outlets::invoke::StreamReservationRecord)
/// is a plain `Clone` serde value, so — like [`caveat_counters_snapshot`] — the
/// snapshot stores the map directly. Exists so EVERY snapshot builder projects
/// this Class-S field through ONE helper, exactly like its siblings. Without
/// persisting it, a crash while a stream's off-mailbox pump is mid-flight would
/// strand the open-time escrow hold + cumulative counter reserve (the pump's
/// close-time settle lands on the respawned generation and is dropped).
pub(in crate::context) fn stream_reservations_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<String, crate::context::outlets::invoke::StreamReservationRecord> {
    state.class_s.stream_reservations.clone()
}

// ---------------------------------------------------------------------------
// 13. decrypt_and_dispatch
// ---------------------------------------------------------------------------

/// Decrypts an incoming envelope and dispatches management/control
/// messages.
pub fn decrypt_and_dispatch(
    deps: &ActorDeps,
    crypto_state: Option<&mut crate::context::actor::state::ContextCryptoState>,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    encrypted_blob: &[u8],
) -> Result<Option<scp_protocol::context::builder::OpenedEnvelope>, ContextError> {
    let decrypt_start = std::time::Instant::now();
    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): open through the actor's OWNED
    // field-granular Class-C `&mut ContextCryptoState` (driven from
    // `deliver_incoming`'s `ClassCMut` view) — byte-identical to the deleted
    // provider `open` twin (the 16 golden tests hold). `process_incoming_sender_key`
    // below stays on the provider (it HPKE-opens with the NODE-RESIDENT wrapping
    // secret — receive-side, NOT in the delete set); the sender-key INSTALL,
    // however, now writes to the ACTOR-owned `cs.sender_key_store.set_unchecked`
    // (the provider store is empty on a taken context — see the KeyResponse arm
    // below), and `local_did` is likewise retained. A `None` crypto
    // state means a context with no MLS group (a broadcast context, which never
    // reaches this MLS-decrypt path — its receive path is author-signed) — fail
    // closed, matching the deleted provider `open`'s "no MLS group" error.
    let cs = crypto_state.ok_or_else(|| {
        ContextError::CryptoFailed(
            "no MLS crypto state for decrypt (context has no group)".to_string(),
        )
    })?;
    let open_result = cs.open(&*deps.clock, context_id_bytes, context_id, encrypted_blob)?;
    crate::metrics::record_decrypt_duration(decrypt_start.elapsed());

    match open_result {
        scp_protocol::context::builder::OpenResult::Application(env) => {
            // ADR-049 PR-6 (read-authority switch): the Supervisor-owned Class-M
            // floor registry is now AUTHORITATIVE for the receive-side
            // `(epoch, sequence)` anti-replay floor. `open()` performed pure
            // decrypt + surfaced `env.receive_floor`; the enforcement is HERE,
            // FAIL-CLOSED. The `?` fires BEFORE any `OpenedEnvelope` is
            // dispatched, so a replayed/reordered envelope decrypts harmlessly
            // and is then rejected — no envelope surfaces (D1 close).
            //
            // F-3 (black-hat): the receive-side overshoot ceiling reads
            // `sender_epochs[sender_did]`, which co-mingles remote per-sender
            // epochs with the LOCAL scalar keyed by `local_did`. This is safe
            // only while `local_did` never appears as a remote sender on its own
            // recv path — assert it rather than split the map (splitting ripples
            // through merge/export/blob format; a violation here is fail-safe).
            debug_assert_ne!(
                env.sender_did.as_str(),
                deps.crypto.local_did(),
                "F-3: local_did must never appear as a remote sender on its own recv path"
            );
            deps.supervisor.check_and_advance_recv_sequence(
                context_id_bytes,
                &env.sender_did,
                env.receive_floor,
                scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE,
            )?;
            Ok(Some(*env))
        }
        scp_protocol::context::builder::OpenResult::Control => Ok(None),
        scp_protocol::context::builder::OpenResult::Management {
            sender_did,
            payload,
        } => {
            tracing::debug!(sender_did = %sender_did, context_id = %context_id, "received MLS-wrapped management message");
            // ADR-049 PR-7 (SCP-CRYPTOMOVE-001) §9.16.2: a management payload is a
            // `SenderKeyDistributionMessage`. Branch on its variant — a PULL
            // REQUEST is ANSWERED on the actor's OWNED crypto state (the answer
            // HPKE-seals to the requester's EPHEMERAL wrapping key, so no signing
            // key is needed — a clean receive-side answer); a RESPONSE is the
            // push-distribution install path.
            let dist = scp_protocol::crypto::sender_keys::SenderKeyDistributionMessage::from_bytes(
                &payload,
            )
            .map_err(|e| ContextError::CryptoFailed(format!("distribution message decode: {e}")))?;
            match dist {
                scp_protocol::crypto::sender_keys::SenderKeyDistributionMessage::KeyRequest(
                    request,
                ) => {
                    // BLACK-P7-1 (identity binding): the actor answer gates BOTH
                    // membership (§9.16.6 Mitigation-1) and the block list on
                    // `request.requester_did` — a PAYLOAD field. It MUST equal the
                    // MLS-authenticated `sender_did`, or a member could request
                    // under a DIFFERENT member's identity: e.g. a BLOCKED member
                    // naming an unblocked one to pass the membership + block gates,
                    // then receiving the sender key sealed to their OWN ephemeral
                    // wrapping key. Bind the two here, before answering. The
                    // requester public key the request signature is verified against
                    // is ALSO resolved from `sender_did` (below), so this makes the
                    // gated DID, the authenticated DID, and the signing key one and
                    // the same.
                    if request.requester_did != sender_did {
                        return Err(ContextError::CryptoFailed(
                            "sender-key request requester_did does not match the \
                             MLS-authenticated sender"
                                .to_string(),
                        ));
                    }
                    // The request's Ed25519 signature is by the requester
                    // (== MLS-authenticated `sender_did`) over its ephemeral
                    // wrapping key. MLS already authenticated `sender_did`; the
                    // request signature additionally binds the ephemeral key, so
                    // resolve the requester's Active verification key to check it.
                    let requester_pk =
                        (deps.key_resolver)(&DID(sender_did.clone()), SigningKeyId::Active)
                            .ok_or_else(|| {
                                ContextError::CryptoFailed(format!(
                                    "cannot resolve requester public key for {sender_did}"
                                ))
                            })?;
                    // The actor answer takes the request as bytes (byte-identical
                    // to the retained oracle); re-serialize the parsed request.
                    let request_bytes = rmp_serde::to_vec_named(&request).map_err(|e| {
                        ContextError::CryptoFailed(format!("request re-serialization: {e}"))
                    })?;
                    // No per-context sender-key block list is resident on the actor
                    // (the blocking-flow wiring into the actor answer path is a
                    // forward-only follow-up, tracked in #2146); the §9.16.6
                    // Mitigation-1 membership gate on the MLS group tree is the live
                    // Sybil defense.
                    let blocked = std::collections::HashSet::new();
                    let now_secs = deps.clock.now_secs();
                    if let Some(sealed) = cs.handle_sender_key_request(
                        context_id_bytes,
                        deps.crypto.local_did(),
                        now_secs,
                        &request_bytes,
                        requester_pk.as_bytes(),
                        &blocked,
                    )? {
                        // Queue the ephemeral-sealed answer for MLS-wrap + transmit
                        // by `drain_and_deliver_sender_keys` after the Class-C view
                        // drops (in `handle_deliver_incoming`). A blocked requester
                        // returns `None` (§9.16.2 silent drop) — nothing queued.
                        cs.pending_distributions.push((sender_did.clone(), sealed));
                    }
                    Ok(None)
                }
                scp_protocol::crypto::sender_keys::SenderKeyDistributionMessage::KeyResponse(_) => {
                    // ADR-049 PR-6 GATE-BEFORE-INSTALL + PR-7 install-onto-ACTOR
                    // fix. `process_incoming_sender_key` HPKE-opens with the
                    // NODE-RESIDENT wrapping secret (unaffected by the crypto move)
                    // and returns the authenticated `(key, epoch)`; the
                    // authoritative Class-M registry gates epoch monotonicity + the
                    // poisoning ceiling FAIL-CLOSED BEFORE install; the install then
                    // writes to the ACTOR's OWNED `cs.sender_key_store`. The provider
                    // store is EMPTY on a taken (actor-owned) context, so the former
                    // `deps.crypto.set_sender_key_unchecked` was a silent no-op — the
                    // latent bug this fixes (D1 close, fail-safe ordering preserved).
                    let (sender_key, epoch) = deps.crypto.process_incoming_sender_key(
                        context_id_bytes,
                        &sender_did,
                        &payload,
                    )?;
                    deps.supervisor.check_and_advance_sender_epoch(
                        context_id_bytes,
                        &sender_did,
                        epoch,
                        scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE,
                    )?;
                    let ctx_id_hex = hex::encode(context_id_bytes);
                    cs.sender_key_store
                        .set_unchecked(&ctx_id_hex, &sender_did, sender_key);
                    Ok(None)
                }
                other => Err(ContextError::CryptoFailed(format!(
                    "unexpected sender-key distribution variant on the receive path: {other:?}"
                ))),
            }
        }
    }
}

/// ADR-049 PR-6 (read-authority switch): advance the LOCAL sender-key epoch
/// floor in the authoritative Class-M registry after a local rotation.
///
/// Call AFTER a local `rotate_sender_key` succeeds, passing the post-rotation
/// local epoch as `epoch`. ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the epoch is now a
/// CALLER-SUPPLIED parameter rather than re-read here: all call sites source it
/// from the actor's
/// [`PerContextState::local_sender_key_epoch`](crate::context::actor::state::PerContextState::local_sender_key_epoch)
/// (read inside the same `commit_class_s_keep` closure that durably persisted the
/// bump) — the read-authority follows the write-authority coherently.
///
/// The floor is advanced in the supervisor registry keyed by the local DID.
/// FAIL-CLOSED: a non-monotonic / overshooting local advance surfaces as a
/// [`ContextError`] (via `From<FloorAdvanceError>`) that the caller `?`-propagates
/// — this registry floor raise is the never-regressing anti-replay backstop, so
/// it is NEVER swallowed even though the sender-key rotation + distribution around
/// it is best-effort (M23). In practice a local rotation advances the scalar
/// monotonically by +1, so this never fires; propagating it is the fail-closed
/// default rather than a rollback the caller must orchestrate.
///
/// # Errors
///
/// Returns [`ContextError::CryptoFailed`] if the registry rejects the local
/// epoch advance (non-monotonic or overshoot).
pub(in crate::context) fn mirror_forward_local_sender_epoch(
    deps: &ActorDeps,
    ctx: &[u8; 32],
    epoch: u64,
) -> Result<(), ContextError> {
    let local_did = deps.crypto.local_did();
    deps.supervisor.check_and_advance_sender_epoch(
        ctx,
        local_did,
        epoch,
        scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 14. validate_and_drain_timeouts
// ---------------------------------------------------------------------------

/// Validates timestamp and sequence, then drains timed-out gaps.
///
/// `downward_auth_sink` (ADR-049 §9, RED-CS3): a `&mut Option<ClassSCommitToken>`
/// POPULATED with a fail-closed-persist obligation if draining a timed-out gap
/// runs consequence enforcement that performs a downward-authorization mutation (a
/// capability suspension or an `AssignRole` demotion), so the cell-holding caller
/// commits it fail-closed.
pub async fn validate_and_drain_timeouts(
    view: &mut ClassCMut<'_>,
    deps: &ActorDeps,
    context_id: &str,
    inner: &scp_protocol::envelope::inner::InnerEnvelope,
    now_ms: u64,
    downward_auth_sink: &mut Option<crate::context::actor::class_s::ClassSCommitToken>,
) -> Result<SequenceCheck, ContextError> {
    // Timestamp validation first.
    let tv = scp_protocol::envelope::validation::TimestampValidator::default();
    tv.validate(inner, now_ms)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    // Sequence check: replay detection + gap detection (§9.8.5).
    let check = view
        .sequence_tracker_mut()
        .validate(inner)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    // Drain timed-out gaps. `drain_timed_out_gaps` bundles the simultaneous
    // `&mut reorder_buffer` + `&sequence_tracker` borrow internally.
    // ADR-056: canonical digest, not a re-hash of the hex id.
    let context_id_bytes = state::context_id_to_bytes(context_id);
    let timed_out = view.drain_timed_out_gaps(now_ms);
    for (gap_info, messages) in timed_out {
        let gap_event = ContextEvent::SequenceGapDetected {
            sender_did: DID(gap_info.sender_did.clone()),
            expected_sequence: gap_info.expected_sequence,
            first_delivered_sequence: gap_info.first_buffered_sequence,
            reason: format!("{:?}", gap_info.reason),
        };
        emit_event_into(
            view.receive_buffer_mut(),
            gap_event,
            context_id,
            deps.event_tx.as_ref(),
        );
        for msg in &messages {
            // Re-check membership and capability.
            if !view.membership_class_c_mut().contains(&msg.sender_did)
                || !view
                    .role_state_class_c_mut()
                    .member_has_capability(&msg.sender_did, &Capability::MessagesWrite)
            {
                continue;
            }
            view.sequence_tracker_mut().advance(
                &msg.inner.context_id,
                &msg.sender_did,
                msg.inner.sequence,
                msg.inner.timestamp,
            );
            let event_name = deliver_plaintext_or_announcement(
                view,
                &msg.sender_did,
                &msg.plaintext,
                context_id,
                deps.event_tx.as_ref(),
            );
            // The GROW arms `downward_auth_sink` directly (no separate
            // `note_downward_auth` call to forget — GAP-A closed).
            let _ = run_buffered_post_delivery(
                view,
                downward_auth_sink,
                context_id,
                &context_id_bytes,
                &msg.sender_did,
                event_name,
                // Dormant: `event_name` here is always `None`
                // (`deliver_plaintext_or_announcement` never appends on
                // receive), so this committer-copied timestamp is not yet
                // consumed. Live only once cross-member leaf replication lands
                // (ADR-051). See `run_buffered_post_delivery`'s param doc.
                msg.inner.timestamp / 1000,
                &*deps.clock,
                &*deps.event_log,
                deps.event_tx.as_ref(),
            )
            .await;
        }
    }

    Ok(check)
}

// ---------------------------------------------------------------------------
// 15. buffer_ahead_message
// ---------------------------------------------------------------------------

/// Buffers an out-of-order message that arrived ahead of expected
/// sequence. Force-delivers oldest gap on overflow.
///
/// `downward_auth_sink` (ADR-049 §9, RED-CS3): a `&mut Option<ClassSCommitToken>`
/// POPULATED with a fail-closed-persist obligation if a force-drained gap message
/// runs consequence enforcement that performs a downward-authorization mutation (a
/// capability suspension or an `AssignRole` demotion), so the cell-holding caller
/// commits it fail-closed.
#[allow(clippy::too_many_arguments)]
pub async fn buffer_ahead_message(
    view: &mut ClassCMut<'_>,
    deps: &ActorDeps,
    context_id: &str,
    inner: &scp_protocol::envelope::inner::InnerEnvelope,
    sender_did: &str,
    plaintext: &[u8],
    now_ms: u64,
    downward_auth_sink: &mut Option<crate::context::actor::class_s::ClassSCommitToken>,
) {
    let buffered_msg = scp_protocol::envelope::validation::BufferedMessage {
        inner: inner.clone(),
        sender_did: sender_did.to_owned(),
        plaintext: plaintext.to_vec(),
        received_at: now_ms,
    };

    if let Some((mut gap_info, messages)) = view.reorder_buffer_mut().buffer(buffered_msg) {
        // ADR-056: canonical digest, not a re-hash of the hex id.
        let context_id_bytes = state::context_id_to_bytes(context_id);
        let expected = view
            .sequence_tracker_mut()
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
            view.receive_buffer_mut(),
            gap_event,
            context_id,
            deps.event_tx.as_ref(),
        );

        for msg in &messages {
            if !view.membership_class_c_mut().contains(&msg.sender_did)
                || !view
                    .role_state_class_c_mut()
                    .member_has_capability(&msg.sender_did, &Capability::MessagesWrite)
            {
                continue;
            }
            view.sequence_tracker_mut().advance(
                &msg.inner.context_id,
                &msg.sender_did,
                msg.inner.sequence,
                msg.inner.timestamp,
            );
            let event_name = deliver_plaintext_or_announcement(
                view,
                &msg.sender_did,
                &msg.plaintext,
                context_id,
                deps.event_tx.as_ref(),
            );
            // The GROW arms `downward_auth_sink` directly (no separate
            // `note_downward_auth` call to forget — GAP-A closed).
            let _ = run_buffered_post_delivery(
                view,
                downward_auth_sink,
                context_id,
                &context_id_bytes,
                &msg.sender_did,
                event_name,
                // Dormant: `event_name` here is always `None`
                // (`deliver_plaintext_or_announcement` never appends on
                // receive), so this committer-copied timestamp is not yet
                // consumed. Live only once cross-member leaf replication lands
                // (ADR-051). See `run_buffered_post_delivery`'s param doc.
                msg.inner.timestamp / 1000,
                &*deps.clock,
                &*deps.event_log,
                deps.event_tx.as_ref(),
            )
            .await;
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
///
/// `downward_auth_sink` (ADR-049 §9, RED-CS3): a `&mut Option<ClassSCommitToken>`
/// POPULATED with a fail-closed-persist obligation if this delivery (or any
/// consecutively-drained buffered message) runs consequence enforcement that
/// performs a downward-authorization mutation (a capability suspension or an
/// `AssignRole` demotion), so the cell-holding caller commits the mutated state
/// fail-closed (keep-direction).
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
pub async fn deliver_message_and_drain_buffered(
    view: &mut ClassCMut<'_>,
    deps: &ActorDeps,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    sender_did: &str,
    inner: &scp_protocol::envelope::inner::InnerEnvelope,
    plaintext: &[u8],
    skip_velocity: bool,
    downward_auth_sink: &mut Option<crate::context::actor::class_s::ClassSCommitToken>,
) -> Result<bool, ContextError> {
    let sender_did_obj = DID(sender_did.to_owned());

    state::require_active(view.handle_mut())?;

    if !view.membership_class_c_mut().contains(sender_did) {
        return Err(ContextError::MemberNotFound(format!(
            "sender {sender_did} is not a member of this context"
        )));
    }
    {
        let role = view.role_state_class_c_mut();
        if !role.member_has_capability(sender_did, &Capability::MessagesWrite) {
            let is_suspended = role
                .suspended_capabilities()
                .get(sender_did)
                .is_some_and(|s| s.contains(&Capability::MessagesWrite));
            let msg = if is_suspended {
                format!("member {sender_did} write access has been revoked")
            } else {
                format!("member {sender_did} does not have messages:write capability")
            };
            return Err(ContextError::PermissionDenied(msg));
        }
    }

    // §9.10.4: run the shared announcement-ingest validator. The direct path
    // maps a rejection to a typed `Err(PermissionDenied)` (there IS a caller to
    // surface it to), and on success runs the in-order follow-up below.
    match ingest_pseudonym_announcement(
        view,
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
            // Recorded by the shared validator (registry insert + a
            // `ContextEvent::PseudonymAnnounced` buffer signal emitted
            // on-change). The remaining
            // follow-up — sequence-tracker advance, reorder-buffer drain,
            // velocity, and consequence evaluation — is specific to the in-order
            // direct path and runs here only. There is NO durable Merkle append:
            // a received announcement is a §9.10.4 routing-bootstrap signal, not a
            // convergent event (per-receiver arrival order; honest members never
            // append on receive), so appending it would false-positive §9.9.3 equivocation
            // detection — the same reason received application messages are
            // buffer-only.
            view.sequence_tracker_mut().advance(
                context_id,
                sender_did,
                inner.sequence,
                inner.timestamp,
            );
            let next_expected = inner.sequence.saturating_add(1);
            let consecutive =
                view.reorder_buffer_mut()
                    .drain_consecutive(context_id, sender_did, next_expected);
            for msg in &consecutive {
                if !view.membership_class_c_mut().contains(&msg.sender_did)
                    || !view
                        .role_state_class_c_mut()
                        .member_has_capability(&msg.sender_did, &Capability::MessagesWrite)
                {
                    continue;
                }
                view.sequence_tracker_mut().advance(
                    &msg.inner.context_id,
                    &msg.sender_did,
                    msg.inner.sequence,
                    msg.inner.timestamp,
                );
                let event_name = deliver_plaintext_or_announcement(
                    view,
                    &msg.sender_did,
                    &msg.plaintext,
                    context_id,
                    deps.event_tx.as_ref(),
                );
                // The GROW arms `downward_auth_sink` directly (no separate
                // `note_downward_auth` call to forget — GAP-A closed).
                let _ = run_buffered_post_delivery(
                    view,
                    downward_auth_sink,
                    context_id,
                    context_id_bytes,
                    &msg.sender_did,
                    event_name,
                    // Dormant: `event_name` here is always `None`
                    // (`deliver_plaintext_or_announcement` never appends on
                    // receive), so this committer-copied timestamp is not yet
                    // consumed. Live only once cross-member leaf replication
                    // lands (ADR-051). See `run_buffered_post_delivery`'s param
                    // doc.
                    msg.inner.timestamp / 1000,
                    &*deps.clock,
                    &*deps.event_log,
                    deps.event_tx.as_ref(),
                )
                .await;
            }

            let now = deps.clock.now_secs();
            if !skip_velocity {
                view.governance_class_c_mut()
                    .velocity_tracker_mut()
                    .record_message(&DID(sender_did.to_owned()), now);
            }
            let consequence_rules: Vec<ConsequenceRule> = view
                .governance_class_c_mut()
                .consequence_rules_mut()
                .clone();
            if !consequence_rules.is_empty() {
                let (recv_events, convergent_now) =
                    crate::context::governance_logic::event_log_entries_for_consequences(
                        view.receive_buffer_mut(),
                        context_id,
                        now,
                        &*deps.event_log,
                    );
                let recv_triggered = evaluate_consequence_rules(
                    &consequence_rules,
                    &recv_events,
                    sender_did,
                    now,
                    convergent_now,
                );
                let recv_member_did = DID(sender_did.to_owned());
                let mut split = view.consequence_split();
                // The GROW arms `downward_auth_sink` directly (GAP-A closed).
                let _ = crate::context::governance_logic::enforce_triggered_consequences(
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
                    downward_auth_sink,
                )
                .await;
            }
            *view.checkpoint_events_since_mut() += 1;

            return Ok(true);
        }
    }

    // Normal message: advance tracker + deliver.
    view.sequence_tracker_mut()
        .advance(context_id, sender_did, inner.sequence, inner.timestamp);
    let recv_event = ContextEvent::MessageReceived {
        sender_did: sender_did_obj,
        payload: plaintext.to_vec(),
    };
    emit_event_into(
        view.receive_buffer_mut(),
        recv_event,
        context_id,
        deps.event_tx.as_ref(),
    );

    // Drain consecutive buffered (§9.8.5).
    let next_expected = inner.sequence.saturating_add(1);
    let consecutive =
        view.reorder_buffer_mut()
            .drain_consecutive(context_id, sender_did, next_expected);
    for msg in &consecutive {
        if !view.membership_class_c_mut().contains(&msg.sender_did)
            || !view
                .role_state_class_c_mut()
                .member_has_capability(&msg.sender_did, &Capability::MessagesWrite)
        {
            continue;
        }
        view.sequence_tracker_mut().advance(
            &msg.inner.context_id,
            &msg.sender_did,
            msg.inner.sequence,
            msg.inner.timestamp,
        );
        let event_name = deliver_plaintext_or_announcement(
            view,
            &msg.sender_did,
            &msg.plaintext,
            context_id,
            deps.event_tx.as_ref(),
        );
        // The GROW arms `downward_auth_sink` directly (GAP-A closed).
        let _ = run_buffered_post_delivery(
            view,
            downward_auth_sink,
            context_id,
            context_id_bytes,
            &msg.sender_did,
            event_name,
            // Dormant: `event_name` here is always `None`
            // (`deliver_plaintext_or_announcement` never appends on receive),
            // so this committer-copied timestamp is not yet consumed. Live only
            // once cross-member leaf replication lands (ADR-051). See
            // `run_buffered_post_delivery`'s param doc.
            msg.inner.timestamp / 1000,
            &*deps.clock,
            &*deps.event_log,
            deps.event_tx.as_ref(),
        )
        .await;
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
        view.governance_class_c_mut()
            .velocity_tracker_mut()
            .record_message(&DID(sender_did.to_owned()), now);
    }
    let consequence_rules: Vec<ConsequenceRule> = view
        .governance_class_c_mut()
        .consequence_rules_mut()
        .clone();
    if !consequence_rules.is_empty() {
        let (recv_events, convergent_now) =
            crate::context::governance_logic::event_log_entries_for_consequences(
                view.receive_buffer_mut(),
                context_id,
                now,
                &*deps.event_log,
            );
        let recv_triggered = evaluate_consequence_rules(
            &consequence_rules,
            &recv_events,
            sender_did,
            now,
            convergent_now,
        );
        let recv_member_did = DID(sender_did.to_owned());
        let mut split = view.consequence_split();
        // The GROW arms `downward_auth_sink` directly (GAP-A closed).
        let _ = crate::context::governance_logic::enforce_triggered_consequences(
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
            downward_auth_sink,
        )
        .await;
    }

    *view.checkpoint_events_since_mut() += 1;
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    handle: &ContextHandle,
    sender_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
) {
    let context_id = handle.context_id().to_owned();
    // Read the routing pseudonym via Deref; the borrow ends before the
    // cell-taking `send_message` call below (which reaches the spending-nonce
    // leaf).
    let Some(pseudonym) = cell.routing.local_pseudonym() else {
        return;
    };
    let announcement = PseudonymAnnouncement {
        tag: PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
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
        cell,
        deps,
        handle,
        sender_did,
        &payload,
        Some(signing_key),
        // Pseudonym announcements are protocol-level membership signals from
        // the local member, signed under `#active` (ADR-039).
        SigningKeyId::Active,
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
    use scp_did::DID;
    use scp_protocol::context::pseudonym::{PSEUDONYM_ANNOUNCEMENT_TAG, PseudonymAnnouncement};

    fn announcement_bytes(member_did: &str, pseudonym: [u8; 32]) -> Vec<u8> {
        let ann = PseudonymAnnouncement {
            tag: PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
            member_did: member_did.to_owned(),
            pseudonym,
        };
        rmp_serde::to_vec_named(&ann).expect("serialize announcement")
    }

    // The pure §9.10.4 predicate + classifier unit tests
    // (`is_reserved_pseudonym`, `pseudonym_collides_with_other_did`,
    // `is_pseudonym_announcement_payload`, `classify_pseudonym_announcement`)
    // moved to `scp_protocol::context::pseudonym` alongside the logic they
    // exercise (ADR-057 T-1). The behavioral ingest tests below STAY here: they
    // drive the native `&mut ClassCMut` wrapper (`ingest_pseudonym_announcement`)
    // against a real `PerContextState`, proving the wrapper's collapse onto the
    // shared classifier is behavior-identical.

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
    use crate::context::actor::class_s::ClassCMut;
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

        let result = deliver_plaintext_or_announcement(
            &mut ClassCMut::from_state(&mut state),
            ALICE,
            &bytes,
            &ctx,
            None,
        );
        // A recorded announcement is a buffer-only routing signal — NO durable
        // Merkle leaf is minted on receive (§9.9.3), so the typed-append channel
        // is `None`. The registry update is the observable effect.
        assert_eq!(result, None);
        // Registry now maps Alice's DID to her announced routing ID.
        let reg = state.routing.peer_registry().expect("encrypted ⇒ registry");
        assert_eq!(reg.get(&DID(ALICE.to_owned())), Some(&alice_pseudonym));
    }

    #[test]
    fn buffered_forged_own_pseudonym_announcement_is_rejected() {
        // S1 (centralized in the shared classifier — ADR-057): BOB forges
        // `BOB → victim_pseudonym`, where `victim_pseudonym` is THIS receiver's own
        // pseudonym. The sender-mismatch guard passes (BOB announces for BOB) and
        // the value is not in the peer registry (which excludes self), but the
        // classifier — given the receiver's own pseudonym via `local_pseudonym()` —
        // rejects it as a collision, so native does NOT record `BOB → our address`.
        // Mirrors the browser `classify_rejects_announcement_of_the_receivers_own_pseudonym`.
        let mut state = encrypted_state();
        let ctx = ctx_hex(0x11);
        let victim_pseudonym = [0x77u8; 32];
        ClassCMut::from_state(&mut state)
            .routing_mut()
            .set_local_pseudonym(victim_pseudonym);

        let result = deliver_plaintext_or_announcement(
            &mut ClassCMut::from_state(&mut state),
            BOB,
            &announcement_bytes(BOB, victim_pseudonym),
            &ctx,
            None,
        );
        // Rejected → no typed-append and (crucially) no registry insert.
        assert_eq!(result, None);
        let reg = state.routing.peer_registry().expect("encrypted ⇒ registry");
        assert!(
            reg.get(&DID(BOB.to_owned())).is_none(),
            "a forged own-pseudonym announcement must NOT be recorded (S1)"
        );
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
                &mut ClassCMut::from_state(&mut state),
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
                &mut ClassCMut::from_state(&mut state),
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

    /// Emit-on-CHANGE: the receive buffer surfaces a `PseudonymAnnounced` event
    /// on a NEW peer and on a CHANGED (rotated) pseudonym, but NOT on an
    /// identical re-announce (the reciprocal cascade re-sends the same value
    /// idempotently). Mirrors the browser client's `ingest_application_plaintext`
    /// predicate so the emit decision cannot drift across targets
    /// (share-don't-fork — ADR-057). Guards the silent-rotation gap: a known
    /// peer that rotates its routing ID MUST surface the change to a stream
    /// watcher, not update the registry silently.
    #[test]
    fn ingest_emits_pseudonym_announced_on_change_only() {
        let mut state = encrypted_state();
        let ctx = ctx_hex(0x11);
        let first = [0x42u8; 32];
        let rotated = [0x43u8; 32];

        let count_events = |s: &PerContextState| {
            s.receive_buffer
                .event_log_entries()
                .iter()
                .filter(|e| {
                    matches!(
                        e,
                        scp_protocol::context::membership::ContextEvent::PseudonymAnnounced { .. }
                    )
                })
                .count()
        };

        // (1) First contact — a NEW peer: emits.
        ingest_pseudonym_announcement(
            &mut ClassCMut::from_state(&mut state),
            ALICE,
            &announcement_bytes(ALICE, first),
            &ctx,
            None,
        );
        assert_eq!(
            count_events(&state),
            1,
            "a first-contact announcement must emit a PseudonymAnnounced event"
        );

        // (2) Identical re-announce — SAME value: registry value is unchanged,
        // so NO new event fires (the reciprocal-cascade dedup).
        ingest_pseudonym_announcement(
            &mut ClassCMut::from_state(&mut state),
            ALICE,
            &announcement_bytes(ALICE, first),
            &ctx,
            None,
        );
        assert_eq!(
            count_events(&state),
            1,
            "an identical re-announce must NOT emit a duplicate PseudonymAnnounced event"
        );

        // (3) Rotation — CHANGED value: emits again, surfacing the address change.
        ingest_pseudonym_announcement(
            &mut ClassCMut::from_state(&mut state),
            ALICE,
            &announcement_bytes(ALICE, rotated),
            &ctx,
            None,
        );
        assert_eq!(
            count_events(&state),
            2,
            "a rotated (changed) pseudonym re-announce must emit a fresh PseudonymAnnounced event"
        );
    }

    #[test]
    fn buffered_sender_did_mismatch_is_dropped_and_leaves_registry_unchanged() {
        let mut state = encrypted_state();
        let ctx = ctx_hex(0x11);
        // The announcement claims BOB but the authenticated sender is ALICE.
        let forged = announcement_bytes(BOB, [0x42u8; 32]);

        let result = deliver_plaintext_or_announcement(
            &mut ClassCMut::from_state(&mut state),
            ALICE,
            &forged,
            &ctx,
            None,
        );
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
                deliver_plaintext_or_announcement(
                    &mut ClassCMut::from_state(&mut state),
                    ALICE,
                    &bytes,
                    &ctx,
                    None
                ),
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
                &mut ClassCMut::from_state(&mut state),
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
                &mut ClassCMut::from_state(&mut state),
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
            deliver_plaintext_or_announcement(
                &mut ClassCMut::from_state(&mut state),
                BOB,
                &bytes,
                &ctx,
                None
            ),
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
        let result = deliver_plaintext_or_announcement(
            &mut ClassCMut::from_state(&mut state),
            ALICE,
            b"hello world",
            &ctx,
            None,
        );
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
            ingest_pseudonym_announcement(
                &mut ClassCMut::from_state(&mut s),
                ALICE,
                b"plain",
                &ctx,
                None
            ),
            AnnouncementOutcome::NotAnnouncement
        ));

        // Recorded: legitimate announcement.
        let mut s = encrypted_state();
        assert!(matches!(
            ingest_pseudonym_announcement(
                &mut ClassCMut::from_state(&mut s),
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
                &mut ClassCMut::from_state(&mut s),
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
    use scp_clock::TestClock;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

    /// Event-log provider that flags which `EventType`s were appended so the
    /// test can prove (a) a non-convergent (velocity-triggered) consequence
    /// appends NO durable `ConsequenceTriggered` Merkle leaf (ADR-051 §6) and
    /// (b) the application message itself appends NO `MessageSent` Merkle leaf
    /// for a `None` event type (§9.9.3). Uses atomics only (no `Mutex`) per
    /// ADR-049's runtime-state model.
    #[derive(Default)]
    struct RecordingEventLog {
        saw_consequence_triggered: AtomicBool,
        saw_message_sent: AtomicBool,
    }

    #[async_trait::async_trait]
    impl crate::context::builder::ContextEventLogProvider for RecordingEventLog {
        async fn init_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }

        async fn append_event(
            &self,
            _id: &[u8; 32],
            event: scp_event_log::EventType,
            _actor: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
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

        async fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn buffered_application_message_runs_velocity_consequence_and_checkpoint() {
        use crate::context::messaging_helpers::{
            deliver_plaintext_or_announcement, run_buffered_post_delivery,
        };
        use scp_protocol::trust::consequence::{
            ConsequenceAction, ConsequenceRule, ConsequenceTrigger, EnforcementSeverity,
        };

        let ctx = ctx_hex(0x11);
        // `ctx` is a real 64-hex id; key it through the ADR-056 chokepoint for
        // fidelity with production keying (decodes the digest, never re-hashes).
        let ctx_bytes = crate::context::state::context_id_to_bytes(&ctx);
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
        let event_name = deliver_plaintext_or_announcement(
            &mut ClassCMut::from_state(&mut state),
            ALICE,
            b"hello world",
            &ctx,
            None,
        );
        assert_eq!(
            event_name, None,
            "a received application message must not mint a durable Merkle leaf"
        );

        // Post-delivery governance MUST run unconditionally, mirroring the
        // in-order path — this is exactly the call shape the four buffered-drain
        // sites now use.
        let mut obligation = None;
        let _suspended = run_buffered_post_delivery(
            &mut ClassCMut::from_state(&mut state),
            &mut obligation,
            &ctx,
            &ctx_bytes,
            ALICE,
            event_name,
            1_700_000_000,
            &clock,
            &event_log,
            None,
        )
        .await;
        // No GROW occurs on this velocity-trigger path, so no obligation is armed.
        assert!(
            obligation.is_none(),
            "a non-GROW post-delivery must not arm a fail-closed obligation"
        );

        // (a) Velocity was recorded for the sender.
        let velocity = state.governance.velocity_tracker.snapshot_entries();
        assert!(
            velocity.get(ALICE).is_some_and(|ts| !ts.is_empty()),
            "buffered application message must record sender velocity (was skipped by the gated bug)"
        );

        // (b) Consequence evaluation + enforcement ran, but a MessageVelocity
        // trigger is NON-CONVERGENT (ADR-051 §6 / phase-2.md ADR-011 amendment):
        // it must NOT mint a durable `ConsequenceTriggered` Merkle leaf (a
        // per-receiver, velocity-derived leaf cannot converge across honest
        // members — §9.9.3), and the application message itself appends no
        // `MessageSent` leaf. That governance DID run is proven by the recorded
        // velocity (a) above and the buffered `ContextEvent::ConsequenceTriggered`
        // surfaced below — local enforcement is unchanged; only the durable leaf
        // is suppressed.
        assert!(
            !event_log
                .saw_consequence_triggered
                .load(AtomicOrdering::SeqCst),
            "a MessageVelocity-triggered consequence is non-convergent and MUST NOT \
             append a durable ConsequenceTriggered Merkle leaf (ADR-051 §6)"
        );
        assert!(
            !event_log.saw_message_sent.load(AtomicOrdering::SeqCst),
            "a received application message must NOT append a MessageSent Merkle leaf (§9.9.3)"
        );
        // The non-durable consequence is still surfaced as a local `ContextEvent`
        // in the receive buffer (the sole surfacing for velocity triggers).
        let saw_triggered_ctx_event = state.receive_buffer.event_log_entries().iter().any(|e| {
            matches!(
                e,
                scp_protocol::context::membership::ContextEvent::ConsequenceTriggered { .. }
            )
        });
        assert!(
            saw_triggered_ctx_event,
            "the non-durable velocity consequence must still emit a \
             ContextEvent::ConsequenceTriggered into the receive buffer"
        );

        // (c) The checkpoint counter advanced for the delivered application
        // message: `run_buffered_post_delivery` increments it once unconditionally
        // for the buffered delivery itself. The velocity consequence adds NO
        // durable leaf and so does NOT additionally advance it (the counter now
        // tracks the true durable-leaf count). The pre-change gated bug left it
        // UNCHANGED entirely.
        assert!(
            state.checkpoint_events_since > checkpoint_before,
            "buffered application message must advance checkpoint_events_since once \
             for the delivery (was skipped by the gated bug): \
             before={checkpoint_before}, after={}",
            state.checkpoint_events_since
        );
    }

    // -----------------------------------------------------------------------
    // STRONGER regression: drive a buffered APPLICATION message END-TO-END
    // through a REAL buffered-drain call site so a re-introduced
    // `if let Some(event_name) { run_buffered_post_delivery(...).await }` gate is
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
    // (velocity recorded + a buffered `ContextEvent::ConsequenceTriggered` +
    // the delivery checkpoint increment) WITHOUT any durable leaf — neither a
    // `MessageSent` leaf nor (for the non-convergent velocity trigger) a durable
    // `ConsequenceTriggered` leaf (ADR-051 §6). Re-adding an `if let Some` gate
    // around the call site makes this test FAIL (governance is skipped for the
    // `None`-typed application message), which the helper-contract test would not
    // catch.
    // -----------------------------------------------------------------------

    /// Event-log provider that records appended `EventType`s through shared
    /// `Arc<AtomicBool>` handles, so the test can read them AFTER the provider
    /// has been moved into the supervisor / `ActorDeps`. Atomics only (no
    /// `Mutex`) per ADR-049's runtime-state model.
    struct DrainRecordingEventLog {
        consequence_triggered: std::sync::Arc<std::sync::atomic::AtomicBool>,
        message_sent: std::sync::Arc<std::sync::atomic::AtomicBool>,
        /// `EventType` enumerates 77 variants; `PseudonymAnnounced` was REMOVED
        /// (it is a `ContextEvent`-only routing signal, not a durable event). A
        /// recorder cannot match a non-existent variant, so a received
        /// announcement is proven buffer-only by the ABSENCE of any append at
        /// all (`any_append == false`) after the announcement-drain path.
        any_append: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl crate::context::builder::ContextEventLogProvider for DrainRecordingEventLog {
        async fn init_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }

        async fn append_event(
            &self,
            _id: &[u8; 32],
            event: scp_event_log::EventType,
            _actor: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
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

        async fn destroy_event_log(
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
            signing_key_id: scp_did::SigningKeyId::Active,
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
        use scp_platform::in_memory::InMemoryStorage;
        use std::sync::Arc;

        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            ALICE.to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let key_resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_, _| None);
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::TestClock::new(1_700_000_000));
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
        let mut downward_auth_applied: Option<crate::context::actor::class_s::ClassSCommitToken> =
            None;
        validate_and_drain_timeouts(
            &mut ClassCMut::from_state(&mut state),
            &deps,
            &ctx,
            &incoming,
            now_ms,
            &mut downward_auth_applied,
        )
        .await
        .expect("validate_and_drain_timeouts");
        // The `SuspendAccess` action is a downward-auth GROW, so the drain
        // populated the sink; discharge it (commit performs the fail-closed persist)
        // so the token's Drop guard is satisfied.
        if let Some(token) = downward_auth_applied.take() {
            let _ = token.commit(&state, &deps, &ctx).await;
        }

        // (a) Velocity recorded for the buffered sender via the drain path.
        let velocity = state.governance.velocity_tracker.snapshot_entries();
        assert!(
            velocity.get(ALICE).is_some_and(|ts| !ts.is_empty()),
            "buffered-drain call site must record sender velocity (a re-added `if let Some` gate skips it)"
        );

        // (b) Consequence evaluation/enforcement ran, but a MessageVelocity
        // trigger is NON-CONVERGENT (ADR-051 §6 / phase-2.md ADR-011 amendment):
        // it must NOT append a durable `ConsequenceTriggered` Merkle leaf, and the
        // application message itself appends no `MessageSent` leaf (§9.9.3). That
        // governance DID run is proven by the recorded velocity (a) above and the
        // buffered `ContextEvent::ConsequenceTriggered` (below) — a re-added
        // `if let Some` gate around the call site would skip BOTH.
        assert!(
            !saw_consequence_triggered.load(AtomicOrdering::SeqCst),
            "a MessageVelocity-triggered consequence is non-convergent and MUST NOT \
             append a durable ConsequenceTriggered Merkle leaf (ADR-051 §6)"
        );
        assert!(
            !saw_message_sent.load(AtomicOrdering::SeqCst),
            "a received application message must NOT append a MessageSent Merkle leaf (§9.9.3)"
        );
        // Governance still surfaced the consequence as a local `ContextEvent`,
        // proving the buffered-drain call site DID run enforcement (a re-added
        // `if let Some` gate would leave the buffer without it).
        let saw_triggered_ctx_event = state.receive_buffer.event_log_entries().iter().any(|e| {
            matches!(
                e,
                scp_protocol::context::membership::ContextEvent::ConsequenceTriggered { .. }
            )
        });
        assert!(
            saw_triggered_ctx_event,
            "the buffered-drain call site must surface a ContextEvent::ConsequenceTriggered \
             for the velocity consequence (a re-added `if let Some` gate skips governance)"
        );

        // (c) The checkpoint counter advanced for the drained application
        // message: the buffered-delivery path increments it once unconditionally.
        // The non-durable velocity consequence adds no leaf and so does not
        // additionally advance it. The gated bug left it unchanged entirely.
        assert!(
            state.checkpoint_events_since > checkpoint_before,
            "buffered-drain call site must advance checkpoint_events_since once for the \
             delivery (a re-added `if let Some` gate skips it): \
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
        // `ctx` is a real 64-hex id; key it through the ADR-056 chokepoint for
        // fidelity with production keying (decodes the digest, never re-hashes).
        let ctx_bytes = crate::context::state::context_id_to_bytes(&ctx);
        let mut state: PerContextState = encrypted_state();

        // The direct delivery path requires an Active context handle.
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
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
        let announcement = PseudonymAnnouncement {
            tag: PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
            member_did: ALICE.to_owned(),
            pseudonym: alice_pseudonym,
        };
        let plaintext = rmp_serde::to_vec_named(&announcement).expect("serialize announcement");
        let inner = drain_test_inner(&ctx, 1);

        let mut downward_auth_applied: Option<crate::context::actor::class_s::ClassSCommitToken> =
            None;
        let consumed = deliver_message_and_drain_buffered(
            &mut ClassCMut::from_state(&mut state),
            &deps,
            &ctx,
            &ctx_bytes,
            ALICE,
            &inner,
            &plaintext,
            false,
            &mut downward_auth_applied,
        )
        .await
        .expect("deliver_message_and_drain_buffered");
        // No consequence rules are installed here, so the sink stays `None`; the
        // `take()` is a no-op that satisfies the token's Drop guard either way.
        if let Some(token) = downward_auth_applied.take() {
            let _ = token.commit(&state, &deps, &ctx).await;
        }

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
    // NATIVE-PARITY FOLLOW-UP (#2179): reciprocal-announce mesh completion.
    //
    // The browser client (`scp-client`) completes the §9.10.4 pseudonym mesh over
    // a real relay via RECIPROCAL-ANNOUNCE: when a member records a NEW peer's
    // pseudonym (a DID not previously in its registry) it re-announces its OWN
    // pseudonym, guarded first-time-per-peer so the cascade converges
    // (joiner-announce seed → existing members reciprocate → joiner reciprocates →
    // quiescent). Native `ingest_pseudonym_announcement` records + emits but does
    // NOT reciprocate.
    //
    // This is a GENUINE external constraint, not a deferral dressed as a decision:
    // the native runtime wires no live relay-receive PUMP today, so a native
    // reciprocal has nothing to drive against and is presently untestable
    // end-to-end. Native must adopt reciprocal-announce in
    // `ingest_pseudonym_announcement` WHEN it wires that live receive pump (#2179),
    // so the trigger lands together with the loop that exercises it.
    //
    // This scaffold exercises the trigger CONDITION today (a first-time new-peer
    // recording — the exact event the reciprocal keys on) against the real native
    // ingest and pins the expected contract. It is #[ignore]d until #2179 wires the
    // receive pump, at which point it is extended to assert the outbound reciprocal
    // announcement (this member's own pseudonym, first-time-per-peer guarded) and
    // un-ignored.
    // -----------------------------------------------------------------------

    #[test]
    #[ignore = "native reciprocal-announce follow-up — see #2179"]
    fn native_reciprocal_announce_on_new_peer_is_a_follow_up() {
        let mut state = encrypted_state();
        let ctx = ctx_hex(0x11);
        // ALICE (this member) holds her own local pseudonym; BOB is a brand-new
        // peer whose announcement ALICE is about to ingest for the first time.
        let alice_pseudonym = [0xA1u8; 32];
        ClassCMut::from_state(&mut state)
            .routing_mut()
            .set_local_pseudonym(alice_pseudonym);

        // Precondition: BOB is NOT yet known — recording him is a FIRST-TIME new
        // peer, the exact event reciprocal-announce keys on.
        assert!(
            state
                .routing
                .peer_registry()
                .expect("encrypted ⇒ registry")
                .get(&DID(BOB.to_owned()))
                .is_none(),
            "BOB must be unknown before the ingest so this is a first-time new-peer recording"
        );

        let bob_pseudonym = [0xB0u8; 32];
        let outcome = ingest_pseudonym_announcement(
            &mut ClassCMut::from_state(&mut state),
            BOB,
            &announcement_bytes(BOB, bob_pseudonym),
            &ctx,
            None,
        );
        assert!(
            matches!(outcome, AnnouncementOutcome::Recorded),
            "a legitimate new-peer announcement is recorded"
        );
        assert_eq!(
            state
                .routing
                .peer_registry()
                .expect("encrypted ⇒ registry")
                .get(&DID(BOB.to_owned())),
            Some(&bob_pseudonym),
            "BOB's pseudonym is now recorded (the first-time trigger fired)"
        );

        // EXPECTED (unmet today — #2179): recording BOB as a NEW peer must drive a
        // RECIPROCAL announcement of ALICE's own pseudonym so BOB learns ALICE — the
        // mesh-completion half of §9.10.4. Native produces no reciprocal here because
        // there is no live receive pump to carry it; when #2179 wires that pump this
        // test asserts the outbound reciprocal announcement is produced, then is
        // un-ignored. Fail loudly if run so the gap is never mistaken for closed.
        panic!(
            "native reciprocal-announce is not implemented — recording a new peer must \
             trigger a reciprocal announcement of this member's own pseudonym (#2179)"
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
            CHECKPOINT_PAYLOAD_TAG, PSEUDONYM_ANNOUNCEMENT_TAG,
            "checkpoint and announcement tags must be distinct"
        );
    }
}
