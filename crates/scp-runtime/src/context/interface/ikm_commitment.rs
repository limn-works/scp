//! `IkmCommitment` — accept-time MLS-exporter IKM + Ed25519 signature
//! under the `SCP-OUTLET-IKM-COMMITMENT-V1:` domain separator.
//!
//! Implements spec §6.2.0.1 step 1 (peer-suffixed MLS exporter) and the
//! "Committed-IKM signing" preimage construction. The struct captures
//! both context ids alongside the IKM and the local epoch so the
//! canonical lexicographic ordering invariant is enforced inside the
//! type — closing the API MINOR OUT-031 round-6 swap-risk flagged in
//! ADR-049 round 6 §"`IkmCommitment` encapsulation".
//!
//! Cryptographic shape (matches §6.2.0.1 byte-for-byte):
//!
//! ```text
//! ikm_local = MLS_EXPORTER(
//!     "scp-context-hop-salt-v1:" || peer_context_id,
//!     b"",
//!     32,
//! )
//!
//! ikm_sig_preimage = SHA-256(
//!     "SCP-OUTLET-IKM-COMMITMENT-V1:"
//!     || len_be32(context_a_id) || context_a_id
//!     || len_be32(context_b_id) || context_b_id
//!     || epoch_be                                  // 8 bytes BE u64
//!     || ikm                                        // 32 bytes
//! )
//!
//! ikm_sig = Ed25519_sign(admin_active_key, ikm_sig_preimage)
//! ```
//!
//! The `(context_a_id, context_b_id)` pair is always laid down in
//! canonical lexicographic order regardless of which side is the
//! "local" context. Both Context A and Context B therefore feed
//! byte-identical preimages into their respective signatures, so a
//! single verifier can re-derive the preimage from the on-wire
//! [`scp_protocol::context::outlets::interface::InterfaceEstablished`]
//! event without knowing which side authored the signature.
//!
//! See:
//! - `.docs/specs/06-cross-context-communication.md` §6.2.0.1
//! - `.docs/specs/09-security-model.md` §9.18.2
//!   (`SCP-OUTLET-IKM-COMMITMENT-V1:` domain separator)
//! - `.docs/adrs/ADR-049-outlet-redesign.md` Round 5 + Round 6

use ed25519_dalek::{SIGNATURE_LENGTH, Signature, Signer, SigningKey, Verifier, VerifyingKey};
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::ContextCryptoProvider;
use scp_protocol::context::outlets::interface::{ContextId, Ed25519Signature};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

/// Domain separator string (UTF-8 bytes) for the `SCP-OUTLET-IKM-COMMITMENT-V1:`
/// preimage. Registered in spec §9.18.2.
///
/// The trailing colon is part of the on-wire prefix per the §9.18.2
/// registration table — every other separator in §9.18.2 ends in a colon
/// and the §6.2.0.1 byte spec includes the colon literal.
pub const IKM_COMMITMENT_DOMAIN_SEPARATOR: &[u8] = b"SCP-OUTLET-IKM-COMMITMENT-V1:";

/// MLS exporter label prefix for accept-time IKM derivation.
///
/// Value: `scp-context-hop-salt-v1:`. Registered in spec §9.18.2 — the
/// per-peer suffix (the peer context id) is appended at derivation time
/// to enforce per-pair isolation (§6.2.0.1 "Why the label suffix is
/// required").
pub const IKM_EXPORTER_LABEL_PREFIX: &[u8] = b"scp-context-hop-salt-v1:";

/// Length of an Ed25519 signature in bytes (matches
/// [`ed25519_dalek::SIGNATURE_LENGTH`]).
const ED25519_SIGNATURE_LENGTH: usize = SIGNATURE_LENGTH;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Signature-verification failures for [`IkmCommitment::verify`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IkmSignatureError {
    /// The signature byte length does not equal 64 (Ed25519 signature length).
    #[error("ikm signature must be {expected} bytes, got {actual}")]
    InvalidLength {
        /// Expected length (always 64 for Ed25519).
        expected: usize,
        /// Actual length supplied by the caller.
        actual: usize,
    },
    /// Cryptographic verification failed — the signature does not authenticate
    /// the canonical preimage under the supplied verifying key.
    ///
    /// Maps to the §6.2.0.1 verifier-rule rejection slug
    /// `authorization.ikm-signature-invalid` (`SCP-TOOL-6110`) when fired
    /// at event-log append time.
    #[error("ikm signature verification failed: {reason}")]
    VerificationFailed {
        /// Human-readable reason for diagnostic logging. Wire-level rejection
        /// uses the typed slug above; this string is for operator triage.
        reason: String,
    },
}

/// Failures during MLS-exporter-backed IKM derivation
/// ([`IkmCommitment::derive_accept_time`]).
#[derive(Debug, Error)]
pub enum IkmCommitmentDeriveError {
    /// The MLS exporter call returned a non-32-byte payload — should not happen
    /// when the exporter is invoked with `length = 32`, but is checked
    /// defensively because the on-wire `ikm` field is `[u8; 32]`.
    #[error("MLS exporter returned {actual} bytes, expected 32 for hop-salt IKM")]
    UnexpectedExporterLength {
        /// The actual byte count returned by the provider.
        actual: usize,
    },
    /// The crypto provider rejected the exporter call (e.g., MLS group
    /// destroyed, no group registered for the context).
    #[error("MLS exporter call failed: {0}")]
    ProviderFailed(#[from] ContextError),
}

// ---------------------------------------------------------------------------
// MlsExporter — minimal trait used by IkmCommitment::derive_accept_time
// ---------------------------------------------------------------------------

/// Minimal trait for invoking the MLS exporter (RFC 9420 §8) at the current
/// group epoch.
///
/// `IkmCommitment::derive_accept_time` is generic over this trait so the
/// runtime can supply either the production [`ContextCryptoProvider`]
/// (via the blanket impl below) or a deterministic in-memory fixture in
/// tests.
pub trait MlsExporter {
    /// Runs `MLS_EXPORTER(label, context, length)` at the current group epoch
    /// for the given `context_id`. Returns exactly `length` bytes of keying
    /// material on success.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if the MLS group is missing,
    /// destroyed, or the exporter call fails.
    fn export_secret(
        &self,
        context_id: &[u8; 32],
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, ContextError>;
}

/// Blanket impl: any [`ContextCryptoProvider`] can drive
/// [`IkmCommitment::derive_accept_time`].
impl<T: ContextCryptoProvider + ?Sized> MlsExporter for T {
    fn export_secret(
        &self,
        context_id: &[u8; 32],
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, ContextError> {
        ContextCryptoProvider::export_secret_for_context(self, context_id, label, context, length)
    }
}

// ---------------------------------------------------------------------------
// IkmCommitment
// ---------------------------------------------------------------------------

/// Accept-time MLS-exporter IKM commitment for one side of a cross-context
/// outlet interface (§6.2.0.1).
///
/// The struct captures the canonical (lexicographically ordered) context
/// pair alongside the IKM and the local epoch so the
/// `SCP-OUTLET-IKM-COMMITMENT-V1:` preimage cannot be assembled with the
/// pair fields swapped — every constructor flows through
/// [`IkmCommitment::new`] which calls [`canonical_pair`]. This closes the
/// API MINOR OUT-031 round-6 swap-risk: building an `IkmCommitment` with
/// `context_a_id`/`context_b_id` arguments swapped produces a
/// byte-identical preimage to the unswapped form, so an attacker cannot
/// forge a "wrong-direction" commitment to forge cross-interface
/// signatures.
///
/// **Zeroization.** [`ZeroizeOnDrop`] is derived so the 32-byte IKM is
/// zeroed when the struct is dropped — the IKM is committed verbatim
/// into the public event log alongside the epoch counter so it is not a
/// long-term secret, but in-memory zeroization closes the residual
/// memory-disclosure surface during the accept-time pipeline.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct IkmCommitment {
    /// 32 bytes of MLS-exporter-derived keying material at accept time.
    pub ikm: [u8; 32],
    /// First context id in canonical (lexicographic ascending) order.
    /// Always `min(local_id, peer_id)` per [`canonical_pair`].
    pub context_a_id: ContextId,
    /// Second context id in canonical (lexicographic ascending) order.
    /// Always `max(local_id, peer_id)` per [`canonical_pair`].
    pub context_b_id: ContextId,
    /// MLS epoch counter on the local context at accept time. Persisted
    /// verbatim into [`InterfaceEstablished::epoch_a`] / `epoch_b`.
    ///
    /// [`InterfaceEstablished::epoch_a`]: scp_protocol::context::outlets::interface::InterfaceEstablished::epoch_a
    pub epoch: u64,
}

impl IkmCommitment {
    /// Constructs an [`IkmCommitment`] with canonical-ordered context pair.
    ///
    /// `local_id` and `peer_id` are reordered through [`canonical_pair`]
    /// so that `context_a_id <= context_b_id` lexicographically, regardless
    /// of which side called this constructor. Both contexts therefore feed
    /// byte-identical preimages into their respective signatures.
    #[must_use]
    pub fn new(ikm: [u8; 32], local_id: &ContextId, peer_id: &ContextId, epoch: u64) -> Self {
        let (a, b) = canonical_pair(local_id, peer_id);
        Self {
            ikm,
            context_a_id: a,
            context_b_id: b,
            epoch,
        }
    }

    /// Computes `MLS_EXPORTER("scp-context-hop-salt-v1:" || peer_id, b"", 32)`
    /// on the local context's MLS group at the supplied accept-time
    /// `epoch`, and returns an [`IkmCommitment`] with canonical-ordered
    /// pair fields (§6.2.0.1 step 1).
    ///
    /// `local_context_id_bytes` is the 32-byte MLS group id of the local
    /// context (the same key used everywhere else by
    /// [`ContextCryptoProvider`]). `local_id` and `peer_id` are the
    /// human-readable string context ids that appear in the
    /// `InterfaceEstablished` event metadata; the per-peer label suffix
    /// (`peer_id.as_bytes()`) makes each per-pair IKM derive from a unique
    /// exporter key per §6.2.0.1 "Why the label suffix is required".
    ///
    /// `epoch` is captured into the returned [`IkmCommitment`] without
    /// re-querying the provider — callers that need the accept-time
    /// epoch persisted into the event MUST resolve it via the provider's
    /// `current_mls_epoch_for_context` BEFORE calling this constructor so
    /// that signature and event field carry the same value.
    ///
    /// # Errors
    ///
    /// Returns [`IkmCommitmentDeriveError::ProviderFailed`] when the MLS
    /// exporter call fails (typically because the MLS group has been
    /// destroyed) and [`IkmCommitmentDeriveError::UnexpectedExporterLength`]
    /// if the provider returns an unexpected length.
    pub fn derive_accept_time<E: MlsExporter + ?Sized>(
        mls: &E,
        local_context_id_bytes: &[u8; 32],
        local_id: &ContextId,
        peer_id: &ContextId,
        epoch: u64,
    ) -> Result<Self, IkmCommitmentDeriveError> {
        // Build the per-peer exporter label per §6.2.0.1 step 1:
        //     "scp-context-hop-salt-v1:" || peer_id.as_bytes()
        // The peer-context suffix is the per-pair isolation lever
        // (§6.2.0.1 "Why the label suffix is required").
        let mut label = Vec::with_capacity(IKM_EXPORTER_LABEL_PREFIX.len() + peer_id.len());
        label.extend_from_slice(IKM_EXPORTER_LABEL_PREFIX);
        label.extend_from_slice(peer_id.as_bytes());

        // RFC 9420 §8 exporter `context` parameter is empty per §6.2.0.1.
        let exporter_bytes = mls.export_secret(local_context_id_bytes, &label, b"", 32)?;
        if exporter_bytes.len() != 32 {
            return Err(IkmCommitmentDeriveError::UnexpectedExporterLength {
                actual: exporter_bytes.len(),
            });
        }
        let mut ikm = [0u8; 32];
        ikm.copy_from_slice(&exporter_bytes[..]);
        Ok(Self::new(ikm, local_id, peer_id, epoch))
    }

    /// Computes the canonical `SCP-OUTLET-IKM-COMMITMENT-V1:` preimage and
    /// signs it under the supplied Ed25519 signing key.
    ///
    /// The preimage is:
    ///
    /// ```text
    /// SHA-256(
    ///     "SCP-OUTLET-IKM-COMMITMENT-V1:"
    ///     || len_be32(context_a_id) || context_a_id
    ///     || len_be32(context_b_id) || context_b_id
    ///     || epoch_be
    ///     || ikm
    /// )
    /// ```
    ///
    /// The `(context_a_id, context_b_id)` pair is canonical-ordered by
    /// [`IkmCommitment::new`] so both sides feed byte-identical
    /// preimages into their signatures.
    #[must_use]
    pub fn sign(&self, signer: &SigningKey) -> Ed25519Signature {
        let preimage = self.canonical_preimage_hash();
        signer.sign(&preimage).to_bytes().to_vec()
    }

    /// Verifies that `sig` authenticates this commitment's canonical preimage
    /// under `verifying_key`.
    ///
    /// # Errors
    ///
    /// - [`IkmSignatureError::InvalidLength`] if `sig` is not exactly 64
    ///   bytes (Ed25519 signature length).
    /// - [`IkmSignatureError::VerificationFailed`] if the cryptographic
    ///   verification fails. The latter maps to the §6.2.0.1 verifier-rule
    ///   rejection slug `authorization.ikm-signature-invalid`
    ///   (`SCP-TOOL-6110`) when fired at event-log append time.
    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        sig: &Ed25519Signature,
    ) -> Result<(), IkmSignatureError> {
        if sig.len() != ED25519_SIGNATURE_LENGTH {
            return Err(IkmSignatureError::InvalidLength {
                expected: ED25519_SIGNATURE_LENGTH,
                actual: sig.len(),
            });
        }
        let mut sig_bytes = [0u8; ED25519_SIGNATURE_LENGTH];
        sig_bytes.copy_from_slice(sig);
        let signature = Signature::from_bytes(&sig_bytes);
        let preimage = self.canonical_preimage_hash();
        verifying_key.verify(&preimage, &signature).map_err(|e| {
            IkmSignatureError::VerificationFailed {
                reason: e.to_string(),
            }
        })
    }

    /// Computes the SHA-256 hash that is signed under the
    /// `SCP-OUTLET-IKM-COMMITMENT-V1:` separator. Returns the 32-byte
    /// digest — Ed25519 signs and verifies the digest directly per
    /// §6.2.0.1.
    #[must_use]
    pub fn canonical_preimage_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(IKM_COMMITMENT_DOMAIN_SEPARATOR);
        // Length-prefixed variable-length fields prevent concatenation
        // ambiguity (e.g., ("ab", "cd") vs ("a", "bcd")).
        // u32 BE matches the spec's `len_be32(...)`.
        let a_len = u32::try_from(self.context_a_id.len()).unwrap_or(u32::MAX);
        let b_len = u32::try_from(self.context_b_id.len()).unwrap_or(u32::MAX);
        hasher.update(a_len.to_be_bytes());
        hasher.update(self.context_a_id.as_bytes());
        hasher.update(b_len.to_be_bytes());
        hasher.update(self.context_b_id.as_bytes());
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.ikm);
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Canonical pair helper
// ---------------------------------------------------------------------------

/// Returns `(context_a_id, context_b_id)` reordered so the lexicographically
/// smaller id is first.
///
/// The §6.2.0.1 invariant: both Context A and Context B must compute
/// byte-identical preimages from their accept-time signatures. They each
/// know one of the two ids as "local" and the other as "peer", so the
/// canonical-ordering step inside [`IkmCommitment::new`] is what makes
/// the construction symmetric.
#[must_use]
pub fn canonical_pair(left: &ContextId, right: &ContextId) -> (ContextId, ContextId) {
    if left <= right {
        (left.clone(), right.clone())
    } else {
        (right.clone(), left.clone())
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
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Deterministic in-memory MLS exporter fixture for unit tests. Maps
    /// `(context_id_bytes, label, context)` to a fixed byte vector.
    #[derive(Default)]
    struct FixtureExporter {
        responses: Mutex<HashMap<(Vec<u8>, Vec<u8>, Vec<u8>), Vec<u8>>>,
    }

    impl FixtureExporter {
        fn insert(&self, ctx_id: &[u8; 32], label: &[u8], context: &[u8], value: Vec<u8>) {
            let mut g = self.responses.lock().unwrap();
            g.insert((ctx_id.to_vec(), label.to_vec(), context.to_vec()), value);
        }
    }

    impl MlsExporter for FixtureExporter {
        fn export_secret(
            &self,
            context_id: &[u8; 32],
            label: &[u8],
            context: &[u8],
            length: usize,
        ) -> Result<zeroize::Zeroizing<Vec<u8>>, ContextError> {
            let g = self.responses.lock().unwrap();
            match g.get(&(context_id.to_vec(), label.to_vec(), context.to_vec())) {
                Some(v) if v.len() == length => Ok(zeroize::Zeroizing::new(v.clone())),
                Some(v) => Err(ContextError::CryptoFailed(format!(
                    "fixture entry length {} != requested {}",
                    v.len(),
                    length
                ))),
                None => Err(ContextError::CryptoFailed(format!(
                    "no fixture entry for label={:?} context={:?}",
                    label, context
                ))),
            }
        }
    }

    fn ctx_a() -> ContextId {
        "ctx-A".to_owned()
    }
    fn ctx_b() -> ContextId {
        "ctx-B".to_owned()
    }
    fn ctx_c() -> ContextId {
        "ctx-C".to_owned()
    }

    fn sample_ikm() -> [u8; 32] {
        let mut v = [0u8; 32];
        for (i, b) in v.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        v
    }

    fn sample_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    // -----------------------------------------------------------------------
    // canonical_pair
    // -----------------------------------------------------------------------

    #[test]
    fn canonical_pair_orders_lexicographically() {
        assert_eq!(canonical_pair(&ctx_b(), &ctx_a()), (ctx_a(), ctx_b()));
        assert_eq!(canonical_pair(&ctx_a(), &ctx_b()), (ctx_a(), ctx_b()));
    }

    #[test]
    fn canonical_pair_handles_equal_ids() {
        assert_eq!(canonical_pair(&ctx_a(), &ctx_a()), (ctx_a(), ctx_a()));
    }

    // -----------------------------------------------------------------------
    // IkmCommitment::new — encapsulation + invariant
    // -----------------------------------------------------------------------

    #[test]
    fn ikm_commitment_new_orders_pair() {
        let c = IkmCommitment::new(sample_ikm(), &ctx_b(), &ctx_a(), 42);
        assert_eq!(c.context_a_id, ctx_a());
        assert_eq!(c.context_b_id, ctx_b());
        assert_eq!(c.epoch, 42);
        assert_eq!(c.ikm, sample_ikm());
    }

    /// AC: Struct-encapsulation swap-bug regression — building an
    /// `IkmCommitment` with `context_a_id`/`context_b_id` arguments swapped
    /// produces a byte-identical preimage to the unswapped form, because
    /// `canonical_pair` reorders the inputs internally.
    #[test]
    fn swap_bug_regression_preimage_byte_identical_under_argument_swap() {
        let unswapped = IkmCommitment::new(sample_ikm(), &ctx_a(), &ctx_b(), 7);
        let swapped = IkmCommitment::new(sample_ikm(), &ctx_b(), &ctx_a(), 7);
        assert_eq!(
            unswapped.canonical_preimage_hash(),
            swapped.canonical_preimage_hash(),
            "canonical_pair must absorb the argument swap so preimages match",
        );
        // Public fields also byte-equal — the swap-risk is closed at the
        // type boundary, not just at the hash boundary.
        assert_eq!(unswapped, swapped);
    }

    // -----------------------------------------------------------------------
    // derive_accept_time — peer-suffixed exporter label
    // -----------------------------------------------------------------------

    #[test]
    fn derive_accept_time_uses_peer_suffixed_label_and_canonical_pair() {
        let exporter = FixtureExporter::default();
        let group_id = [0xAB; 32];
        // Local = ctx-A, peer = ctx-B → exporter label suffix is ctx-B's
        // bytes. Spec §6.2.0.1: A's exporter is labeled with B's id.
        let mut expected_label = IKM_EXPORTER_LABEL_PREFIX.to_vec();
        expected_label.extend_from_slice(ctx_b().as_bytes());
        exporter.insert(&group_id, &expected_label, b"", sample_ikm().to_vec());

        let c = IkmCommitment::derive_accept_time(&exporter, &group_id, &ctx_a(), &ctx_b(), 99)
            .expect("exporter fixture should drive derive_accept_time");
        assert_eq!(c.ikm, sample_ikm());
        assert_eq!(c.context_a_id, ctx_a());
        assert_eq!(c.context_b_id, ctx_b());
        assert_eq!(c.epoch, 99);
    }

    #[test]
    fn derive_accept_time_swapped_local_peer_uses_local_peer_label_but_canonical_pair() {
        // When the local context is B and the peer is A, the MLS exporter
        // is labeled with A's id (the PEER suffix), but the preimage pair
        // is still (A, B) because `IkmCommitment::new` canonicalizes.
        let exporter = FixtureExporter::default();
        let group_id = [0xCD; 32];
        let mut expected_label = IKM_EXPORTER_LABEL_PREFIX.to_vec();
        expected_label.extend_from_slice(ctx_a().as_bytes());
        exporter.insert(&group_id, &expected_label, b"", sample_ikm().to_vec());

        let c = IkmCommitment::derive_accept_time(&exporter, &group_id, &ctx_b(), &ctx_a(), 99)
            .expect("exporter fixture should drive derive_accept_time");
        // Pair must be canonical regardless of which side called.
        assert_eq!(c.context_a_id, ctx_a());
        assert_eq!(c.context_b_id, ctx_b());
    }

    #[test]
    fn derive_accept_time_propagates_provider_error() {
        let exporter = FixtureExporter::default(); // no entries
        let group_id = [0xAA; 32];
        let err = IkmCommitment::derive_accept_time(&exporter, &group_id, &ctx_a(), &ctx_b(), 1)
            .expect_err("missing fixture entry must propagate as provider error");
        match err {
            IkmCommitmentDeriveError::ProviderFailed(_) => {}
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // sign / verify roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn sign_then_verify_roundtrip() {
        let signer = sample_signing_key(0x11);
        let vk = signer.verifying_key();
        let c = IkmCommitment::new(sample_ikm(), &ctx_a(), &ctx_b(), 5);
        let sig = c.sign(&signer);
        c.verify(&vk, &sig).expect("genuine signature must verify");
        assert_eq!(sig.len(), ED25519_SIGNATURE_LENGTH);
    }

    /// AC: a tampered `ikm_a_sig` (last byte flipped) rejects with
    /// `authorization.ikm-signature-invalid` — i.e.
    /// [`IkmSignatureError::VerificationFailed`].
    #[test]
    fn tampered_signature_last_byte_flipped_rejects() {
        let signer = sample_signing_key(0x22);
        let vk = signer.verifying_key();
        let c = IkmCommitment::new(sample_ikm(), &ctx_a(), &ctx_b(), 11);
        let mut sig = c.sign(&signer);
        let last = sig.last_mut().expect("ed25519 sig is 64 bytes");
        *last ^= 0x01;
        let err = c
            .verify(&vk, &sig)
            .expect_err("tampered signature must fail verification");
        match err {
            IkmSignatureError::VerificationFailed { .. } => {}
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn invalid_length_signature_rejects() {
        let vk = sample_signing_key(0x33).verifying_key();
        let c = IkmCommitment::new(sample_ikm(), &ctx_a(), &ctx_b(), 11);
        let bad_sig: Ed25519Signature = vec![0u8; 32]; // wrong length
        match c
            .verify(&vk, &bad_sig)
            .expect_err("short signature must reject")
        {
            IkmSignatureError::InvalidLength { expected, actual } => {
                assert_eq!(expected, 64);
                assert_eq!(actual, 32);
            }
            other => panic!("expected InvalidLength, got {other:?}"),
        }
    }

    /// AC: an `ikm_a` value from interface A↔B with A's signature does NOT
    /// verify when replayed as the ikm in an A↔C `InterfaceEstablished`
    /// event — the context-id pair is in the preimage, so a signature for
    /// A↔B cannot be reused for A↔C.
    #[test]
    fn cross_interface_replay_signature_does_not_verify() {
        let signer = sample_signing_key(0x44);
        let vk = signer.verifying_key();
        // Sign for the A↔B interface.
        let ab = IkmCommitment::new(sample_ikm(), &ctx_a(), &ctx_b(), 17);
        let sig_ab = ab.sign(&signer);

        // Construct an A↔C commitment using the SAME ikm value, then attempt
        // to verify A's A↔B signature against the A↔C preimage. Verification
        // must fail because the (ctx_a, ctx_c) pair is in the preimage and
        // differs from the (ctx_a, ctx_b) pair signed above.
        let ac = IkmCommitment::new(ab.ikm, &ctx_a(), &ctx_c(), 17);
        let err = ac
            .verify(&vk, &sig_ab)
            .expect_err("cross-interface replay must not verify");
        match err {
            IkmSignatureError::VerificationFailed { .. } => {}
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
    }

    /// Different epochs must produce different signatures (preimage binds
    /// `epoch`).
    #[test]
    fn epoch_binding_in_preimage() {
        let signer = sample_signing_key(0x55);
        let c1 = IkmCommitment::new(sample_ikm(), &ctx_a(), &ctx_b(), 1);
        let c2 = IkmCommitment::new(sample_ikm(), &ctx_a(), &ctx_b(), 2);
        let sig1 = c1.sign(&signer);
        let sig2 = c2.sign(&signer);
        assert_ne!(sig1, sig2);
        // sig1 must NOT verify against c2 (different preimage)
        assert!(c2.verify(&signer.verifying_key(), &sig1).is_err());
    }

    // -----------------------------------------------------------------------
    // Domain separator literal (defense in depth — keeps spec sync explicit)
    // -----------------------------------------------------------------------

    #[test]
    fn domain_separator_literal_matches_spec_text() {
        assert_eq!(
            IKM_COMMITMENT_DOMAIN_SEPARATOR,
            b"SCP-OUTLET-IKM-COMMITMENT-V1:"
        );
    }

    #[test]
    fn exporter_label_prefix_matches_spec_text() {
        assert_eq!(IKM_EXPORTER_LABEL_PREFIX, b"scp-context-hop-salt-v1:");
    }

    /// AC: the canonical preimage matches a deterministic golden vector —
    /// guards against accidental changes to the byte layout (length prefix
    /// width, field order, BE vs LE epoch encoding).
    #[test]
    fn canonical_preimage_golden_vector() {
        let c = IkmCommitment::new([0x42; 32], &"a".to_owned(), &"b".to_owned(), 1);
        // Hand-rolled expected hash:
        //   SHA-256(
        //     "SCP-OUTLET-IKM-COMMITMENT-V1:"
        //     || 00000001 || "a"
        //     || 00000001 || "b"
        //     || 0000000000000001
        //     || [0x42; 32]
        //   )
        let mut expected = Sha256::new();
        expected.update(b"SCP-OUTLET-IKM-COMMITMENT-V1:");
        expected.update(1u32.to_be_bytes());
        expected.update(b"a");
        expected.update(1u32.to_be_bytes());
        expected.update(b"b");
        expected.update(1u64.to_be_bytes());
        expected.update([0x42; 32]);
        let expected: [u8; 32] = expected.finalize().into();
        assert_eq!(c.canonical_preimage_hash(), expected);
    }
}
