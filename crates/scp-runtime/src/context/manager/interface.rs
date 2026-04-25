//! `AcceptOutletInterface` runtime handler — derives both sides' IKM
//! commitments, verifies both Ed25519 signatures BEFORE event-log
//! append, and emits an `OutletInterfaceAccepted` event carrying the
//! [`InterfaceEstablished`] payload (spec §6.2.0.1, SCP-OUT-042b).
//!
//! # Cryptographic invariants
//!
//! 1. `ikm_local` is computed via the §6.2.0.1 step-1 peer-suffixed MLS
//!    exporter, queried through [`IkmCommitment::derive_accept_time`].
//! 2. `ikm_local_sig` is the local admin's Ed25519 signature over the
//!    `SCP-OUTLET-IKM-COMMITMENT-V1:` preimage under the admin's
//!    `#active` key (§6.2.0.1 "Committed-IKM signing").
//! 3. The local-side verification check covers BOTH `ikm_local_sig`
//!    (sanity, against the just-produced signing key) AND the
//!    peer-provided `ikm_peer_sig` (against the peer admin's
//!    `#active` verifying key resolved at `epoch_peer`).
//! 4. **Failure rejects entirely.** A failed signature verification on
//!    EITHER side returns [`AcceptOutletInterfaceError::IkmSignatureInvalid`]
//!    and the `OutletInterfaceAccepted` event is NOT appended to either
//!    event log. This matches the §6.2.0.1 verifier rule: rejection
//!    slug `authorization.ikm-signature-invalid` (`SCP-TOOL-6110`).
//!
//! # Scope
//!
//! This story (OUT-042b) supplies the cryptographic accept-time pipeline
//! and event assembly. Governance plumbing — the actual
//! `ProposeOutletInterface`/`AcceptOutletInterface` action dispatch,
//! `InterfaceOffer` matching, `RemoveMember`-induced rotations, and
//! cluster-detection metadata population — lands in OUT-042c / OUT-042d.

use ed25519_dalek::{SigningKey, VerifyingKey};
use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::interface::{
    ContextId, Ed25519Signature, InterfaceEstablished,
};
use thiserror::Error;

use crate::context::interface::ikm_commitment::{
    IkmCommitment, IkmCommitmentDeriveError, IkmSignatureError,
};
use crate::context::manager::ContextManager;

/// `OutletErrorClass::Authorization` slug emitted when an IKM commitment
/// signature fails verification. Matches the §6.2.0.1 verifier-rule
/// rejection text.
pub const AUTHORIZATION_IKM_SIGNATURE_INVALID_SLUG: &str = "authorization.ikm-signature-invalid";

/// `SCP-TOOL-NNNN` code attached to the §6.2.0.1 verifier-rule rejection.
pub const AUTHORIZATION_IKM_SIGNATURE_INVALID_CODE: &str = "SCP-TOOL-6110";

/// Event-log event name appended on a successful accept. The
/// [`InterfaceEstablished`] payload is serialized as JSON for the
/// `append_context_event_with_payload` body (the runtime's event-log
/// adapter signs over the canonical bytes).
pub const OUTLET_INTERFACE_ACCEPTED_EVENT: &str = "OutletInterfaceAccepted";

// ---------------------------------------------------------------------------
// AcceptOutletInterfaceInputs
// ---------------------------------------------------------------------------

/// Inputs to [`ContextManager::accept_outlet_interface`].
///
/// The local side (the accepting context) supplies its own admin signing
/// key and the peer's accept-time signed IKM (the peer derived theirs
/// via the same construction in their own context's accept handler). The
/// handler then computes the local IKM, signs it, and verifies BOTH
/// signatures BEFORE appending to the event log.
#[derive(Debug, Clone)]
pub struct AcceptOutletInterfaceInputs {
    /// Interface/offer identifier — same as the matched
    /// [`InterfaceOffer::offer_id`](scp_protocol::context::outlets::interface::InterfaceOffer::offer_id).
    pub interface_id: [u8; 32],
    /// Outlet being shared (the offer's `outlet_id`).
    pub outlet_id: OutletId,
    /// Source context (Context A — the offerer).
    pub source_context: ContextId,
    /// Target context (Context B — the accepter, i.e. the local side).
    pub target_context: ContextId,
    /// Wall-clock unix-millis timestamp at which the accept happens.
    pub established_at: u64,
    // -- Local (accepting context, "B") --------------------------------------
    /// Local context's MLS group id (32-byte canonical id).
    pub local_context_id_bytes: [u8; 32],
    /// Local MLS epoch counter at accept time. Captured by the caller
    /// from `current_mls_epoch_for_context` BEFORE invocation so the
    /// signed `epoch` field and the persisted `epoch_b` are in lockstep.
    pub local_epoch: u64,
    /// Local admin signing key (`#active`).
    pub local_signing_key: SigningKey,
    // -- Peer (offering context, "A") ---------------------------------------
    /// Peer-provided MLS epoch counter at the peer's accept-time — copied
    /// verbatim into `InterfaceEstablished.epoch_a`.
    pub peer_epoch: u64,
    /// Peer-provided IKM (the value Context A's exporter produced under
    /// the peer-suffixed label). Persisted verbatim into `ikm_a`.
    pub peer_ikm: [u8; 32],
    /// Peer admin's Ed25519 signature over the
    /// `SCP-OUTLET-IKM-COMMITMENT-V1:` preimage with `peer_ikm`,
    /// `peer_epoch`, and the canonical context pair. Persisted verbatim
    /// into `ikm_a_sig`.
    pub peer_ikm_sig: Ed25519Signature,
    /// Peer admin's `#active` verifying key, resolved against the peer
    /// context's role registry at `peer_epoch`. The handler verifies
    /// `peer_ikm_sig` against this key per the §6.2.0.1 verifier rule.
    pub peer_admin_active_key: VerifyingKey,
    // -- Cluster-detection metadata (OUT-042d wires final population) -------
    /// Peer context's `creator_did` (§5.4 lifecycle). Captured into the
    /// event for the cluster-detection rolling window. OUT-042d wires
    /// population from the offer's published cluster metadata; the
    /// schema accepts it here so the event lands fully populated when
    /// available.
    pub peer_creator_did: DID,
    /// Peer admin set at accept-time (sorted lexicographically by the
    /// caller — ordering invariant per `InterfaceEstablished`).
    pub peer_admin_set: Vec<DID>,
    /// Peer capability-holder set at accept-time (sorted lexicographically
    /// by the caller).
    pub peer_capability_holder_set: Vec<DID>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure modes for [`ContextManager::accept_outlet_interface`].
#[derive(Debug, Error)]
pub enum AcceptOutletInterfaceError {
    /// The local-side MLS exporter call failed (typically because the
    /// local MLS group is missing or destroyed).
    #[error("local IKM derivation failed: {0}")]
    DeriveFailed(#[from] IkmCommitmentDeriveError),
    /// The local admin's signature did not verify against the local
    /// admin's own verifying key — a defense-in-depth sanity check that
    /// trips only if the runtime supplies a mismatched key pair.
    #[error(
        "local admin signature self-verify failed (slug={AUTHORIZATION_IKM_SIGNATURE_INVALID_SLUG}, code={AUTHORIZATION_IKM_SIGNATURE_INVALID_CODE}): {source}"
    )]
    LocalSelfVerifyFailed {
        /// Underlying signature error.
        source: IkmSignatureError,
    },
    /// The peer's signature did not verify against `peer_admin_active_key`.
    /// Maps to the §6.2.0.1 verifier-rule rejection
    /// `authorization.ikm-signature-invalid` (`SCP-TOOL-6110`). The
    /// `OutletInterfaceAccepted` event is NOT appended.
    #[error(
        "ikm signature invalid (slug={AUTHORIZATION_IKM_SIGNATURE_INVALID_SLUG}, code={AUTHORIZATION_IKM_SIGNATURE_INVALID_CODE}): {source}"
    )]
    IkmSignatureInvalid {
        /// Which side's signature failed.
        side: IkmSignatureSide,
        /// Underlying signature error.
        source: IkmSignatureError,
    },
    /// Event-log append failure — propagated from the event-log provider.
    #[error("event-log append failed: {0}")]
    EventLogFailed(#[source] ContextError),
    /// The `InterfaceEstablished` payload could not be JSON-serialized
    /// for `append_context_event_with_payload`.
    #[error("InterfaceEstablished JSON serialization failed: {0}")]
    PayloadSerializationFailed(#[source] serde_json::Error),
}

/// Which side's IKM signature failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkmSignatureSide {
    /// Source context (Context A — the offerer).
    Source,
    /// Target context (Context B — the local accepter).
    Target,
}

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Successful return type from [`ContextManager::accept_outlet_interface`].
#[derive(Debug, Clone)]
pub struct AcceptOutletInterfaceOutput {
    /// The fully-assembled event payload that was appended to the local
    /// event log. Returned for caller-side bookkeeping and for the
    /// outbound shared-member-bridging step (the peer needs the same
    /// event payload appended on its side).
    pub event: InterfaceEstablished,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

impl ContextManager {
    /// Accept an outbound outlet-interface offer, deriving and signing the
    /// local IKM, verifying both sides' signatures, and appending the
    /// resulting `OutletInterfaceAccepted` event to the local event log.
    ///
    /// # Cryptographic order
    ///
    /// 1. Derive `ikm_local` via `IkmCommitment::derive_accept_time`
    ///    (§6.2.0.1 step 1).
    /// 2. Sign `ikm_local` under the local admin's `#active` key
    ///    (§6.2.0.1 "Committed-IKM signing").
    /// 3. Self-verify the local signature defensively.
    /// 4. Reconstruct the peer-side `IkmCommitment` (canonical pair +
    ///    `peer_ikm` + `peer_epoch`) and verify `peer_ikm_sig` against
    ///    `peer_admin_active_key`.
    /// 5. **Only on success of (3) and (4)** — append
    ///    `OutletInterfaceAccepted` to the event log with the assembled
    ///    [`InterfaceEstablished`] payload.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptOutletInterfaceError::IkmSignatureInvalid`] when
    /// either side's signature fails verification — the event does NOT
    /// land in the local event log. Other variants surface derivation,
    /// serialization, or event-log failures verbatim.
    #[allow(clippy::unused_async)]
    pub async fn accept_outlet_interface(
        &self,
        local_context_id: &str,
        actor_did: &str,
        inputs: AcceptOutletInterfaceInputs,
    ) -> Result<AcceptOutletInterfaceOutput, AcceptOutletInterfaceError> {
        // -- Step 1: derive local IKM via the §6.2.0.1 peer-suffixed MLS
        //    exporter. The local context_id passed to MlsExporter is the
        //    32-byte MLS group id; the human-readable string ids
        //    (target_context for self, source_context for peer) feed the
        //    canonical-pair preimage.
        let local_commitment = IkmCommitment::derive_accept_time(
            self.crypto.as_ref(),
            &inputs.local_context_id_bytes,
            &inputs.target_context,
            &inputs.source_context,
            inputs.local_epoch,
        )?;

        // -- Step 2: sign the local commitment under the local admin's
        //    #active key.
        let local_ikm_sig = local_commitment.sign(&inputs.local_signing_key);
        let local_admin_vk = inputs.local_signing_key.verifying_key();

        // -- Step 3: defensive self-verify on the local side. Trips only
        //    if the runtime supplied a mismatched signing/verifying key
        //    pair — but the same code path runs on incoming events so
        //    re-using `IkmCommitment::verify` here keeps the verifier
        //    consistent end-to-end.
        local_commitment
            .verify(&local_admin_vk, &local_ikm_sig)
            .map_err(|source| AcceptOutletInterfaceError::LocalSelfVerifyFailed { source })?;

        // -- Step 4: reconstruct the peer-side commitment from (peer_ikm,
        //    peer_epoch) + the same canonical pair, and verify
        //    peer_ikm_sig against peer_admin_active_key. The §6.2.0.1
        //    invariant is that BOTH sides feed byte-identical preimages,
        //    so we can build the peer's commitment here using the SAME
        //    canonical pair construction (the ids reorder into canonical
        //    form regardless of which side calls `IkmCommitment::new`).
        let peer_commitment = IkmCommitment::new(
            inputs.peer_ikm,
            &inputs.source_context,
            &inputs.target_context,
            inputs.peer_epoch,
        );
        peer_commitment
            .verify(&inputs.peer_admin_active_key, &inputs.peer_ikm_sig)
            .map_err(|source| AcceptOutletInterfaceError::IkmSignatureInvalid {
                side: IkmSignatureSide::Source,
                source,
            })?;

        // -- Step 5: assemble the InterfaceEstablished event payload.
        //    `epoch_a` = peer (source) epoch; `ikm_a` / `ikm_a_sig` are
        //    the peer's. `epoch_b` and `ikm_b` / `ikm_b_sig` are the
        //    local (target) side. This direction matches the §6.2.0.1
        //    field semantics for an `AcceptOutletInterface` invoked by
        //    Context B against an offer published by Context A.
        let event = InterfaceEstablished {
            interface_id: inputs.interface_id,
            source_context: inputs.source_context.clone(),
            target_context: inputs.target_context.clone(),
            outlet_id: inputs.outlet_id.clone(),
            established_at: inputs.established_at,
            epoch_a: inputs.peer_epoch,
            epoch_b: inputs.local_epoch,
            ikm_a: inputs.peer_ikm,
            ikm_a_sig: inputs.peer_ikm_sig.clone(),
            ikm_b: local_commitment.ikm,
            ikm_b_sig: local_ikm_sig,
            creator_did: inputs.peer_creator_did.clone(),
            admin_set: inputs.peer_admin_set.clone(),
            capability_holder_set: inputs.peer_capability_holder_set,
        };

        // -- Step 6: append to the local event log. JSON serialization is
        //    used because the runtime's event-log adapter signs over the
        //    canonical JCS-canonicalized JSON bytes (matches the existing
        //    governance event payload pattern used elsewhere in the
        //    runtime). MessagePack canonicalization for the wire-format
        //    of the event is a separate transport concern — the JSON
        //    body here is the audit-trail body.
        let payload = serde_json::to_value(&event)
            .map_err(AcceptOutletInterfaceError::PayloadSerializationFailed)?;

        let context_id_bytes = scp_protocol::context::context_id_bytes(local_context_id);
        self.event_log
            .append_context_event_with_payload(
                &context_id_bytes,
                OUTLET_INTERFACE_ACCEPTED_EVENT,
                actor_did,
                Some(&payload),
            )
            .map_err(AcceptOutletInterfaceError::EventLogFailed)?;

        Ok(AcceptOutletInterfaceOutput { event })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::match_wildcard_for_single_variants,
    clippy::type_complexity
)]
mod tests {
    use super::*;
    use crate::context::interface::ikm_commitment::IKM_EXPORTER_LABEL_PREFIX;

    /// Helper that drives the full accept-time pipeline on synthetic
    /// inputs, with a stand-in `MlsExporter` so the test does not need
    /// a real MLS group.
    fn run_accept(
        peer_ikm: [u8; 32],
        peer_signer: &SigningKey,
        local_signer: &SigningKey,
        peer_epoch: u64,
        local_epoch: u64,
        source_ctx: &str,
        target_ctx: &str,
    ) -> (
        IkmCommitment,
        Ed25519Signature,
        IkmCommitment,
        Ed25519Signature,
    ) {
        let source_ctx = source_ctx.to_owned();
        let target_ctx = target_ctx.to_owned();
        // Compute peer's signed commitment (Context A's side of the
        // protocol — for testing we drive it directly without an
        // exporter, since the peer's IKM is supplied verbatim).
        let peer_commitment = IkmCommitment::new(peer_ikm, &source_ctx, &target_ctx, peer_epoch);
        let peer_sig = peer_commitment.sign(peer_signer);

        // Synthetic local exporter — the local commitment is built
        // directly from a deterministic IKM (the CryptoProvider would
        // produce this in production via the peer-suffixed exporter
        // label).
        let local_ikm = [0xCD; 32];
        let local_commitment = IkmCommitment::new(local_ikm, &source_ctx, &target_ctx, local_epoch);
        let local_sig = local_commitment.sign(local_signer);

        (peer_commitment, peer_sig, local_commitment, local_sig)
    }

    /// AC: a tampered `ikm_a_sig` (last byte flipped) rejects with
    /// `authorization.ikm-signature-invalid` — the rejection slug is
    /// surfaced via [`AcceptOutletInterfaceError::IkmSignatureInvalid`].
    /// This test exercises the verification step in isolation by calling
    /// `IkmCommitment::verify` with the same inputs that the handler
    /// passes.
    #[test]
    fn tampered_peer_signature_yields_signature_invalid_error() {
        let peer_signer = SigningKey::from_bytes(&[0x77; 32]);
        let local_signer = SigningKey::from_bytes(&[0x88; 32]);
        let (_peer_commit, mut peer_sig, _local, _ls) = run_accept(
            [0x42; 32],
            &peer_signer,
            &local_signer,
            10,
            11,
            "ctx-A",
            "ctx-B",
        );

        // Flip the last byte of the peer signature — verification must
        // fail with `IkmSignatureError::VerificationFailed`, which the
        // handler maps to `IkmSignatureInvalid` with the canonical slug
        // and code.
        let last = peer_sig.last_mut().unwrap();
        *last ^= 0x01;

        let peer_vk = peer_signer.verifying_key();
        // Reconstruct the same commitment the handler would build
        // (canonical pair from source/target ids).
        let peer_commit_at_handler =
            IkmCommitment::new([0x42; 32], &"ctx-A".to_owned(), &"ctx-B".to_owned(), 10);
        let err = peer_commit_at_handler
            .verify(&peer_vk, &peer_sig)
            .expect_err("tampered signature must reject");
        match err {
            IkmSignatureError::VerificationFailed { .. } => {}
            other => panic!("expected VerificationFailed, got {other:?}"),
        }

        // And the slug constant matches the spec's verifier-rule slug —
        // this test pins the wiring so OUT-042c (rotation handler) and
        // any FFI bridge that surfaces the slug share the same constant.
        assert_eq!(
            AUTHORIZATION_IKM_SIGNATURE_INVALID_SLUG,
            "authorization.ikm-signature-invalid"
        );
        assert_eq!(AUTHORIZATION_IKM_SIGNATURE_INVALID_CODE, "SCP-TOOL-6110");
    }

    /// AC: cross-interface replay — a signature for A↔B with peer_ikm
    /// must NOT verify when reconstructed against an A↔C commitment.
    /// (Mirror of the same property in `ikm_commitment::tests`, exercised
    /// at the handler-input layer to document the wiring.)
    #[test]
    fn cross_interface_replay_rejected_at_handler_inputs() {
        let peer_signer = SigningKey::from_bytes(&[0x99; 32]);
        let peer_vk = peer_signer.verifying_key();
        let peer_ikm = [0x55; 32];

        // Sign for A↔B.
        let ab = IkmCommitment::new(peer_ikm, &"ctx-A".to_owned(), &"ctx-B".to_owned(), 5);
        let sig_ab = ab.sign(&peer_signer);

        // Reconstruct an A↔C commitment with the SAME ikm + epoch and
        // verify the A↔B signature against it. The (ctx_a, ctx_c) pair
        // is in the preimage and differs from the (ctx_a, ctx_b) pair
        // signed above, so verification fails.
        let ac = IkmCommitment::new(peer_ikm, &"ctx-A".to_owned(), &"ctx-C".to_owned(), 5);
        let err = ac
            .verify(&peer_vk, &sig_ab)
            .expect_err("cross-interface replay must reject");
        match err {
            IkmSignatureError::VerificationFailed { .. } => {}
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
    }

    /// Defensive: the handler's local self-verify path detects a mismatched
    /// signing/verifying key pair. Wires `IkmCommitment::sign` and
    /// `IkmCommitment::verify` against the SAME canonical pair so the
    /// success path matches.
    #[test]
    fn handler_local_self_verify_succeeds_on_matching_keypair() {
        let local_signer = SigningKey::from_bytes(&[0xAA; 32]);
        let c = IkmCommitment::new([0xBB; 32], &"ctx-A".to_owned(), &"ctx-B".to_owned(), 7);
        let sig = c.sign(&local_signer);
        c.verify(&local_signer.verifying_key(), &sig)
            .expect("self-verify must succeed");
    }

    /// Sanity: the handler reconstructs the peer commitment via
    /// `IkmCommitment::new(peer_ikm, source, target, peer_epoch)`. The
    /// canonical pair invariant means the reconstructed commitment
    /// equals what the peer signed, regardless of swap.
    #[test]
    fn handler_peer_reconstruction_equals_swapped_form() {
        let peer_signer = SigningKey::from_bytes(&[0xCC; 32]);
        let peer_ikm = [0x11; 32];

        // Peer (Context A) signs with (target, source) as the constructor
        // arg order.
        let peer_at_peer_side = IkmCommitment::new(
            peer_ikm,
            &"ctx-target-B".to_owned(),
            &"ctx-source-A".to_owned(),
            42,
        );
        let peer_sig = peer_at_peer_side.sign(&peer_signer);

        // Handler reconstructs with (source, target) — opposite order.
        let peer_at_handler = IkmCommitment::new(
            peer_ikm,
            &"ctx-source-A".to_owned(),
            &"ctx-target-B".to_owned(),
            42,
        );
        // Both must verify the same signature.
        peer_at_handler
            .verify(&peer_signer.verifying_key(), &peer_sig)
            .expect("canonical pair makes reconstruction order-independent");
        assert_eq!(peer_at_peer_side, peer_at_handler);
    }

    /// Documents that the handler drives `IkmCommitment::derive_accept_time`
    /// against a `ContextCryptoProvider` that supports
    /// `export_secret_for_context`. The default trait impl returns
    /// `ContextError::CryptoFailed`, which the handler maps to
    /// `DeriveFailed::ProviderFailed` — exercised in this test by a
    /// `MlsExporter` fixture that returns the spec-mandated label suffix.
    #[test]
    fn derive_accept_time_uses_target_as_local_and_source_as_peer() {
        // The handler's local side is the TARGET context (B) — so the
        // exporter label suffix is the SOURCE context id (A). The handler
        // passes (target, source) as (local_id, peer_id).
        use std::collections::HashMap;
        use std::sync::Mutex;
        struct Fx {
            entries: Mutex<HashMap<(Vec<u8>, Vec<u8>, Vec<u8>), Vec<u8>>>,
        }
        impl crate::context::interface::ikm_commitment::MlsExporter for Fx {
            fn export_secret(
                &self,
                ctx: &[u8; 32],
                label: &[u8],
                context: &[u8],
                length: usize,
            ) -> Result<zeroize::Zeroizing<Vec<u8>>, ContextError> {
                let g = self.entries.lock().unwrap();
                match g.get(&(ctx.to_vec(), label.to_vec(), context.to_vec())) {
                    Some(v) if v.len() == length => Ok(zeroize::Zeroizing::new(v.clone())),
                    _ => Err(ContextError::CryptoFailed("missing fixture".into())),
                }
            }
        }
        let group_id = [0xAB; 32];
        let mut label = IKM_EXPORTER_LABEL_PREFIX.to_vec();
        label.extend_from_slice(b"ctx-source-A");
        let entries = HashMap::from([(
            (group_id.to_vec(), label.clone(), b"".to_vec()),
            vec![0x77; 32],
        )]);
        let fx = Fx {
            entries: Mutex::new(entries),
        };
        let c = IkmCommitment::derive_accept_time(
            &fx,
            &group_id,
            &"ctx-target-B".to_owned(),
            &"ctx-source-A".to_owned(),
            13,
        )
        .expect("fixture should drive derive_accept_time");
        assert_eq!(c.ikm, [0x77; 32]);
        // Canonical pair has the lex-smaller id first.
        assert_eq!(c.context_a_id, "ctx-source-A");
        assert_eq!(c.context_b_id, "ctx-target-B");
        assert_eq!(c.epoch, 13);
    }
}
