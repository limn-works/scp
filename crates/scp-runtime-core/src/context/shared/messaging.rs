//! Items the messaging domain shares with core and with other domains.
//!
//! It holds code that reads or writes only core state and calls no domain
//! function, and the types and constants more than one crate names (ADR-070
//! Appendix).
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::state;
use crate::context::supervisor::MessageSigner;
use scp_clock::Clock;
use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_protocol::crypto::access_keys::AccessKey;
use scp_protocol::crypto::access_keys::wrapping::Recipient;
use scp_protocol::envelope::inner::InnerEnvelope;
use scp_protocol::envelope::inner::InnerEnvelopeParams;
use scp_protocol::envelope::inner::MessageType;
use scp_protocol::provenance::attach::SourceContextInfo;
use std::sync::Arc;

/// Builds and signs the [`InnerEnvelope`] for an application-data send (access-key
/// wrap → inner-envelope stamp+sign), returning it alongside the canonical
/// 32-byte context-id digest.
///
/// Shared by both seal seams — the deleted pre-PR-7 provider path and the
/// ADR-049 PR-7 actor path ([`ContextCryptoState::seal`](crate::context::actor::state::ContextCryptoState::seal)
/// driven from the Class-C view in `scp_runtime_messaging::helpers::encrypt_and_send`, via
/// [`build_encrypted_envelope_actor`]) — so both bottom out in ONE
/// inner-envelope construction and the sealed wire stays byte-identical across
/// the flip (the 16 golden byte-identity tests continue to hold).
///
/// # Errors
///
/// [`ContextError::CryptoFailed`] when the access-key wrap or the content
/// serialization fails, and the signing error when custody does not sign.
#[allow(clippy::too_many_arguments)]
pub async fn build_inner_wire<S: std::hash::BuildHasher + Sync>(
    clock: &Arc<dyn Clock>,
    context_id: &str,
    sender_did: &DID,
    payload: &[u8],
    signer: MessageSigner<'_>,
    recipients_data: &std::collections::HashMap<String, AccessKey, S>,
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

    // ADR-049 Decision 7a: the canonical hash is signed through custody
    // within the signing budget; the actor holds no key material.
    let inner =
        crate::envelope::inner::sign::create_inner_envelope_signed(&params, signer.signer())
            .await?;

    Ok((inner, context_id_bytes))
}

/// Builds and seals an application-data send through the ADR-049 PR-7 actor
/// crypto state (Class-C `&mut ContextCryptoState`), the field-granular crypto
/// sub-state reached via `ClassCMut::mode_mut()`.
///
/// Byte-identical to the deleted pre-PR-7 provider seal path: it shares
/// [`build_inner_wire`] and passes the caller-supplied `aad_sequence` (the
/// authoritative sender-layer AAD sequence — today
/// `MembershipState::next_sequence_number`, matching what the provider's `seal`
/// derived from the inner envelope). `local_did` is sourced from
/// `deps.crypto.local_did()` so the sealed sender-layer AAD binds the same
/// local identity the provider used.
///
/// # Errors
///
/// The error of [`build_inner_wire`], or the seal's error.
#[allow(clippy::too_many_arguments)]
// ADR-049 PR-7 (SCP-CRYPTOMOVE-001): widened from module-private so the relocated
// app-data send-path callers (crypto/mls/provider.rs `encrypt_and_send`, and tests
// outside core through `build_encrypted_envelope_actor_for_test`) can drive the
// PRODUCTION actor app-data seal after the deleted provider twin
// `build_encrypted_envelope` is removed. `pub(crate)` is the minimal correct
// visibility: callers span `crypto/mls/provider.rs` and `context/`, so a
// `pub(super)` / `pub(in crate::context)` cap would wrongly forbid the crypto/mls
// caller (E0624). A domain crate seals through `ActorDeps::build_encrypted_envelope`
// (ADR-070 §4). It is a purely internal crate seam with no FFI/SDK surface, so it
// carries no cross-layer bridge-export requirement. `redundant_pub_crate` is a
// false positive here for the same reason as `Supervisor::build_actor_deps`: the
// enclosing module is `pub(crate)`, but the item is genuinely reached crate-wide.
#[allow(clippy::redundant_pub_crate)]
pub(crate) async fn build_encrypted_envelope_actor<S: std::hash::BuildHasher + Sync>(
    clock: &Arc<dyn Clock>,
    crypto_state: &mut crate::context::actor::state::ContextCryptoState,
    local_did: &str,
    context_id: &str,
    sender_did: &DID,
    payload: &[u8],
    signer: MessageSigner<'_>,
    recipients_data: &std::collections::HashMap<String, AccessKey, S>,
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
    )
    .await?;
    // The serialized MLS message; the transport frames it once for each
    // per-member pseudonym address it fans out to (ADR-002, spec 23 §23.4.1).
    crypto_state.seal(&context_id_bytes, local_did, &inner, aad_sequence)
}

/// Test-only reach into [`build_encrypted_envelope_actor`] for tests outside
/// this crate.
///
/// Those tests seal against a standalone crypto state with a clock and local
/// DID of their choosing. Compiled only under `testing`, so no production or
/// bridge build reaches it (ADR-070 §4).
///
/// # Errors
///
/// Every error [`build_encrypted_envelope_actor`] returns.
#[cfg(any(test, feature = "testing"))]
pub async fn build_encrypted_envelope_actor_for_test(
    clock: &Arc<dyn Clock>,
    crypto_state: &mut crate::context::actor::state::ContextCryptoState,
    local_did: &str,
    request: EncryptedEnvelopeRequest<'_>,
) -> Result<Vec<u8>, ContextError> {
    let EncryptedEnvelopeRequest {
        context_id,
        sender_did,
        payload,
        signer,
        recipients_data,
        aad_sequence,
        source_provenance,
        message_type,
    } = request;
    build_encrypted_envelope_actor(
        clock,
        crypto_state,
        local_did,
        context_id,
        sender_did,
        payload,
        signer,
        recipients_data,
        aad_sequence,
        source_provenance,
        message_type,
    )
    .await
}

/// The per-send inputs of [`ActorDeps::build_encrypted_envelope`]; the clock
/// and the local DID come from the `ActorDeps` itself.
pub struct EncryptedEnvelopeRequest<'r> {
    /// The context the message is sent in.
    pub context_id: &'r str,
    /// The DID the message is sent as.
    pub sender_did: &'r DID,
    /// The application payload.
    pub payload: &'r [u8],
    /// The key and stamped persona that sign the inner envelope.
    pub signer: MessageSigner<'r>,
    /// Each recipient's access key, by member DID.
    pub recipients_data: &'r std::collections::HashMap<String, AccessKey>,
    /// The sender-layer AAD sequence (`MembershipState::next_sequence_number`).
    pub aad_sequence: u64,
    /// The source context, when the payload crossed a context boundary.
    pub source_provenance: Option<&'r SourceContextInfo>,
    /// The message type the envelope carries.
    pub message_type: MessageType,
}

impl ActorDeps {
    /// Builds and seals an application-data send through `crypto_state`, with
    /// this actor's clock and local DID (the sealed sender-layer AAD binds the
    /// identity the actor runs as).
    ///
    /// Domain crates call it through the `ActorDeps` core lends their trait
    /// method; core calls [`build_encrypted_envelope_actor`] directly
    /// (ADR-070 §4).
    ///
    /// # Errors
    ///
    /// Every error [`build_encrypted_envelope_actor`] returns.
    pub async fn build_encrypted_envelope(
        &self,
        crypto_state: &mut crate::context::actor::state::ContextCryptoState,
        request: EncryptedEnvelopeRequest<'_>,
    ) -> Result<Vec<u8>, ContextError> {
        let EncryptedEnvelopeRequest {
            context_id,
            sender_did,
            payload,
            signer,
            recipients_data,
            aad_sequence,
            source_provenance,
            message_type,
        } = request;
        build_encrypted_envelope_actor(
            &self.clock,
            crypto_state,
            self.crypto.local_did(),
            context_id,
            sender_did,
            payload,
            signer,
            recipients_data,
            aad_sequence,
            source_provenance,
            message_type,
        )
        .await
    }
}

/// Discharges a deferred spending-nonce commit token and returns the error.
///
/// A `send_message` EARLY-ABORT path calls it with its
/// [`ClassSCommitToken`](crate::context::actor::class_s::ClassSCommitToken)
/// (ADR-049 §9, keep-direction) and propagates the returned error.
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

/// What `scp_runtime_messaging::helpers::decrypt_and_dispatch` made of one inbound envelope.
#[derive(Debug)]
pub enum Dispatched {
    /// An application envelope for the caller to verify and classify.
    Envelope(Box<scp_protocol::context::builder::OpenedEnvelope>),
    /// A Commit another member committed, already admitted and merged. The
    /// caller classifies its membership changes (spec 09 §9.10.4.1).
    Commit {
        /// The committer's DID from its MLS credential.
        committer_did: String,
        /// The DID of every occupied leaf before and after the Commit.
        leaf_dids: scp_protocol::context::pseudonym::CommitLeafDids,
    },
    /// An MLS Proposal or a management message, processed here.
    Handled,
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
pub fn mirror_forward_local_sender_epoch(
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
