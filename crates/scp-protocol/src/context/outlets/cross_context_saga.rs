//! Cross-context outlet invocation saga signed types (spec §6.2.4).
//!
//! This module defines the two signed protocol types produced by the
//! `CrossContextOutletInvocation` saga's terminal paths:
//!
//! - [`CrossContextOutletReceipt`] — the target's signed response on the return
//!   path. It is **self-verifying**: every field of the signature preimage is
//!   carried on the receipt, so a verifier reconstructs the preimage from the
//!   receipt alone. The one thing the receipt cannot establish about itself is
//!   *signer authorization* — that the signing key is in fact the Active Signing
//!   Key authorized to act for `target_context_id`. A consumer MUST resolve that
//!   key out-of-band via the target context's membership/governance (§3, §7) and
//!   pass it to [`CrossContextOutletReceipt::verify`]; the receipt is never trusted
//!   to name its own authorizing key.
//!
//! - [`CrossContextDivergenceMarker`] — the signed marker both sides emit on a
//!   `NeedsRepair` outcome (Dual event-log recording, §6.2.4). It records which
//!   side committed, the `SagaId`, the `nonce`, and the committed-side event id,
//!   making a one-sided commit durably auditable rather than a silent repudiation
//!   primitive.
//!
//! Both preimages use the §9.5.1 canonical hash construction (domain-separated,
//! field-enumerated, length-prefixed variable fields) — never raw concatenation,
//! which would be splice-ambiguous across the variable-length string fields.
//!
//! Domain separators (registered in §9.18.2):
//! - `"SCP-XCTX-RECEIPT-V1:"` — cross-context outlet receipt signing.
//! - `"SCP-XCTX-DIVERGENCE-V1:"` — cross-context divergence marker signing.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::canonical::{CanonicalField, canonical_hash};

/// Domain separator for [`CrossContextOutletReceipt`] signature preimages (§6.2.4, §9.18.2).
pub const XCTX_RECEIPT_DOMAIN: &str = "SCP-XCTX-RECEIPT-V1:";

/// Domain separator for [`CrossContextDivergenceMarker`] signature preimages (§6.2.4, §9.18.2).
pub const XCTX_DIVERGENCE_DOMAIN: &str = "SCP-XCTX-DIVERGENCE-V1:";

/// Errors produced while signing or verifying cross-context saga types (§6.2.4).
///
/// Error codes use the `SCP-SAGA-` band (`13000-13999`, ADR-049 §3a;
/// see `.docs/standards/sdk-common.md`). The code is embedded in each message
/// so the `check-error-codes.sh` gate can enumerate and range-check it.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CrossContextSagaError {
    /// A canonical-hash field exceeded the `u32::MAX` length-prefix ceiling.
    ///
    /// In practice unreachable: protocol messages are bounded to 256 KB by the
    /// envelope layer (§9.10.3). Present to eliminate a panic path.
    #[error("SCP-SAGA-13000: canonical preimage construction failed: {0}")]
    PreimageConstruction(String),

    /// The Ed25519 signature did not verify against the reconstructed preimage.
    #[error("SCP-SAGA-13001: Ed25519 signature verification failed: {0}")]
    SignatureInvalid(String),

    /// The signing key offered is not a well-formed Ed25519 verifying key.
    #[error("SCP-SAGA-13002: malformed Ed25519 verifying key: {0}")]
    MalformedKey(String),
}

/// Which side of the cross-context saga committed when the saga diverged.
///
/// On a `NeedsRepair` outcome exactly one side may have committed (e.g. B
/// executed and charged while A's settle did not land, or the reverse). The
/// committed side is named here so operator repair can reconcile the escrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommittedSide {
    /// The initiating (caller) context committed its `CrossContextOutletInvoked` record.
    Caller,
    /// The executing (target) context committed its `OutletInvoked` record.
    Target,
}

impl CommittedSide {
    /// Stable 1-byte discriminator for the canonical preimage.
    ///
    /// Encoded as a `U8` so the committed side is bound into the signature.
    /// The mapping is fixed (`Caller = 0`, `Target = 1`) and versioned by the
    /// `SCP-XCTX-DIVERGENCE-V1:` separator.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Caller => 0,
            Self::Target => 1,
        }
    }
}

/// Compute `output_hash = SHA-256(jcs-canonical output bytes)` (§6.2.4).
///
/// The input is the receipt's carried output bytes — the exact JCS serialization
/// the signer hashed. The verifier recomputes directly from these bytes with no
/// re-canonicalization step (Output canonicalization obligation, §6.2.4).
fn output_hash(output_jcs: &[u8]) -> [u8; 32] {
    Sha256::digest(output_jcs).into()
}

/// The target's signed response on the cross-context outlet invocation return path
/// (§6.2.4, *Receipt / response return path*).
///
/// The receipt carries every field of its signature preimage plus the target's
/// Ed25519 signature, so it is **self-verifying** from its own fields — except
/// for *signer authorization*, which the consumer MUST supply (see [`Self::verify`]).
///
/// # Field semantics (normative, §6.2.4)
///
/// - `caller_context_id` / `target_context_id` — raw 32-byte context-id digests
///   (`Fixed32` in the preimage, 64-hex on the wire). Never the `"standing-"`-
///   prefixed display string (§5.15.8 id-form rule).
/// - `nonce` — the staged 16-byte correlation/dedup token (B's copy of the wire
///   nonce). It is the join key between the two event-log records.
/// - `chain_depth` — **B's re-derived inbound depth** (`incoming + 1`), identical
///   to the value B wrote into `OutletInvoked`, never the caller-asserted envelope
///   value. A `u8` per §6.2.0 (`max_chain_depth` range `[1, 255]`).
/// - `timestamp_ms` — **B's Prepare-B capture instant** (the staged
///   `recorded_timestamp_ms`, "when the target accepted the call"), never the
///   caller's send time.
/// - `output_jcs` — the output as its **JCS-canonical bytes** (the exact
///   serialization the signer hashed). The preimage covers
///   `output_hash = SHA-256(output_jcs)`, not these bytes directly, keeping the
///   caller log free of a large/sensitive payload while preserving a verifiable
///   link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossContextOutletReceipt {
    /// Raw 32-byte digest of the initiating (caller) context.
    #[serde(with = "crate::serde_util::serde_hash_32")]
    pub caller_context_id: [u8; 32],
    /// Raw 32-byte digest of the executing (target) context — the context B
    /// verified and executed the outlet in.
    #[serde(with = "crate::serde_util::serde_hash_32")]
    pub target_context_id: [u8; 32],
    /// The caller principal DID the receipt is issued to (confused-deputy binding).
    pub caller_did: String,
    /// Staged 16-byte correlation/dedup nonce (B's copy of the wire value).
    #[serde(with = "crate::serde_util::serde_nonce_16")]
    pub nonce: [u8; 16],
    /// Context-local outlet registration id B executed (indexes B's own registry).
    pub outlet_registration_id: String,
    /// The output as its JCS-canonical bytes — the exact preimage of `output_hash`.
    #[serde(with = "crate::serde_util::serde_bounded_bytes")]
    pub output_jcs: Vec<u8>,
    /// The target's `OutletInvoked` event-log entry id this receipt links to.
    pub outlet_invoked_event_id: String,
    /// B's re-derived inbound chain depth (`incoming + 1`), never caller-asserted.
    pub chain_depth: u8,
    /// B's Prepare-B capture instant in Unix milliseconds (staged `recorded_timestamp_ms`).
    pub timestamp_ms: u64,
    /// The target's Ed25519 signature over [`Self::signing_preimage`].
    #[serde(with = "crate::serde_util::serde_signature_64")]
    pub signature: [u8; 64],
}

/// The unsigned field set for [`CrossContextOutletReceipt::sign`], named so the
/// call site cannot transpose same-typed arguments.
///
/// [`CrossContextOutletReceipt::sign`] otherwise takes the two adjacent `[u8; 32]`
/// ids (`caller_context_id` / `target_context_id`) and three `String` fields
/// (`caller_did` / `outlet_registration_id` / `outlet_invoked_event_id`) as
/// positional arguments — a transposition surface strictly wider than the
/// invocation envelope the same named-field pattern already closes one layer up.
/// A swap of any same-typed pair compiles and signs a self-consistent-but-wrong
/// receipt.
/// Naming every field at the call site makes a swap a compile-visible field-name
/// error. Per the Agent-first API tenet: one flat named-field object, no builder,
/// no ordering to track.
///
/// The target's Active Signing Key stays a SEPARATE parameter of
/// [`CrossContextOutletReceipt::sign`] — it is signing capability material, not a
/// receipt field, so folding it in would mix the receipt's data with the
/// capability that authorizes it.
pub struct CrossContextOutletReceiptFields {
    /// Raw 32-byte digest of the initiating (caller) context.
    pub caller_context_id: [u8; 32],
    /// Raw 32-byte digest of the executing (target) context.
    pub target_context_id: [u8; 32],
    /// The caller principal DID the receipt is issued to (confused-deputy binding).
    pub caller_did: String,
    /// Staged 16-byte correlation/dedup nonce (B's copy of the wire value).
    pub nonce: [u8; 16],
    /// Context-local outlet registration id B executed (indexes B's own registry).
    pub outlet_registration_id: String,
    /// The output as its JCS-canonical bytes — the exact preimage of `output_hash`.
    pub output_jcs: Vec<u8>,
    /// The target's `OutletInvoked` event-log entry id this receipt links to.
    pub outlet_invoked_event_id: String,
    /// B's re-derived inbound chain depth (`incoming + 1`), never caller-asserted.
    pub chain_depth: u8,
    /// B's Prepare-B capture instant in Unix milliseconds (staged `recorded_timestamp_ms`).
    pub timestamp_ms: u64,
}

impl CrossContextOutletReceipt {
    /// Recompute `output_hash` from the carried JCS-canonical output bytes (§6.2.4).
    #[must_use]
    pub fn output_hash(&self) -> [u8; 32] {
        output_hash(&self.output_jcs)
    }

    /// Build the §9.5.1 canonical signing preimage for this receipt.
    ///
    /// Field order is **normative** (§6.2.4, *Receipt / response return path*):
    /// `Fixed32(caller_context_id)`, `Fixed32(target_context_id)`,
    /// `VarBytes(caller_did)`, `RawBytes16(nonce)`, `VarBytes(outlet_registration_id)`,
    /// `Fixed32(output_hash)`, `VarBytes(outlet_invoked_event_id)`, `U8(chain_depth)`,
    /// `U64(timestamp_ms)`. `output_hash` is `SHA-256(output_jcs)`, recomputed
    /// from the carried bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CrossContextSagaError::PreimageConstruction`] only if a
    /// variable-length field exceeds `u32::MAX` bytes (unreachable in practice;
    /// §9.10.3 bounds messages to 256 KB).
    pub fn signing_preimage(&self) -> Result<[u8; 32], CrossContextSagaError> {
        let output_hash = self.output_hash();
        canonical_hash(
            XCTX_RECEIPT_DOMAIN,
            &[
                CanonicalField::Fixed32(&self.caller_context_id),
                CanonicalField::Fixed32(&self.target_context_id),
                CanonicalField::VarBytes(self.caller_did.as_bytes()),
                CanonicalField::RawBytes(&self.nonce),
                CanonicalField::VarBytes(self.outlet_registration_id.as_bytes()),
                CanonicalField::Fixed32(&output_hash),
                CanonicalField::VarBytes(self.outlet_invoked_event_id.as_bytes()),
                CanonicalField::U8(self.chain_depth),
                CanonicalField::U64(self.timestamp_ms),
            ],
        )
        .map_err(|e| CrossContextSagaError::PreimageConstruction(e.to_string()))
    }

    /// Fields needed to construct and sign a [`CrossContextOutletReceipt`].
    ///
    /// `output_jcs` MUST already be the JCS-canonical serialization of the outlet
    /// output (`jcs::to_string(output).into_bytes()`); the receipt carries those
    /// exact bytes so the verifier can recompute `output_hash` without
    /// re-canonicalizing (§6.2.4 Output canonicalization obligation).
    ///
    /// # Errors
    ///
    /// Returns [`CrossContextSagaError::PreimageConstruction`] if the preimage
    /// cannot be built (unreachable in practice; §9.10.3 bounds messages to 256 KB).
    pub fn sign(
        target_signing_key: &SigningKey,
        fields: CrossContextOutletReceiptFields,
    ) -> Result<Self, CrossContextSagaError> {
        let CrossContextOutletReceiptFields {
            caller_context_id,
            target_context_id,
            caller_did,
            nonce,
            outlet_registration_id,
            output_jcs,
            outlet_invoked_event_id,
            chain_depth,
            timestamp_ms,
        } = fields;
        let mut receipt = Self {
            caller_context_id,
            target_context_id,
            caller_did,
            nonce,
            outlet_registration_id,
            output_jcs,
            outlet_invoked_event_id,
            chain_depth,
            timestamp_ms,
            signature: [0u8; 64],
        };
        let preimage = receipt.signing_preimage()?;
        receipt.signature = target_signing_key.sign_prehashed_preimage(&preimage);
        Ok(receipt)
    }

    /// Verify a cross-context outlet receipt (§6.2.4).
    ///
    /// Verification performs, in order:
    /// 1. recompute `output_hash` from the carried JCS-canonical output bytes;
    /// 2. reconstruct the §9.5.1 signature preimage;
    /// 3. check the Ed25519 signature against `authorized_target_signing_key`.
    ///
    /// **Signer authorization (normative, §6.2.4).** The caller MUST pass the
    /// **Active Signing Key authorized to act for `target_context_id`**, resolved
    /// via the target context's membership/governance (§3, §7). This function
    /// does NOT trust the receipt to name its own authorizing key — a receipt is
    /// self-verifying for *internal consistency*, but a key that does not in fact
    /// control `target_context_id` could otherwise sign a receipt naming it. By
    /// requiring the resolved key as an input, signature validity here is
    /// equivalent to "signed by the key authorized for `target_context_id`".
    ///
    /// # Errors
    ///
    /// - [`CrossContextSagaError::PreimageConstruction`] if the preimage cannot
    ///   be built (unreachable in practice).
    /// - [`CrossContextSagaError::SignatureInvalid`] if the signature does not
    ///   verify against the reconstructed preimage and the supplied key.
    pub fn verify(
        &self,
        authorized_target_signing_key: &VerifyingKey,
    ) -> Result<(), CrossContextSagaError> {
        let preimage = self.signing_preimage()?;
        let signature = Signature::from_bytes(&self.signature);
        authorized_target_signing_key
            .verify_strict(&preimage, &signature)
            .map_err(|e| CrossContextSagaError::SignatureInvalid(e.to_string()))
    }
}

/// The signed divergence marker both sides emit on a `NeedsRepair` outcome
/// (§6.2.4, *Dual event-log recording*).
///
/// A silent one-sided commit is a repudiation primitive (B executed and charged,
/// A denies the call, or the reverse). The marker makes the divergence durably
/// auditable: it records which side committed, the `SagaId`, the `nonce`, and the
/// committed-side event id, signed so operator repair can settle the escrow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossContextDivergenceMarker {
    /// The saga identifier shared by both sides of the cross-context invocation.
    pub saga_id: String,
    /// The 16-byte correlation nonce joining the two event-log records.
    #[serde(with = "crate::serde_util::serde_nonce_16")]
    pub nonce: [u8; 16],
    /// Which side committed (the other side's record is absent).
    pub committed_side: CommittedSide,
    /// The committed side's event-log entry id.
    pub committed_event_id: String,
    /// The signer's Ed25519 signature over [`Self::signing_preimage`].
    #[serde(with = "crate::serde_util::serde_signature_64")]
    pub signature: [u8; 64],
}

/// The unsigned field set for [`CrossContextDivergenceMarker::sign`], named so
/// the call site cannot transpose its two adjacent `String` arguments.
///
/// [`CrossContextDivergenceMarker::sign`] otherwise takes `saga_id` and
/// `committed_event_id` as positional `String`s — a swap compiles and signs a
/// self-consistent-but-wrong marker (the saga id and the committed-side event
/// id reversed). Naming every field at the call site makes a swap a
/// compile-visible field-name error, symmetric with
/// [`CrossContextOutletReceiptFields`]. Per the Agent-first API tenet: one flat
/// named-field object, no builder, no ordering to track.
///
/// The emitting side's signing key stays a SEPARATE parameter of
/// [`CrossContextDivergenceMarker::sign`] — it is signing capability material,
/// not a marker field.
pub struct CrossContextDivergenceMarkerFields {
    /// The saga identifier shared by both sides of the cross-context invocation.
    pub saga_id: String,
    /// The 16-byte correlation nonce joining the two event-log records (B's
    /// staged `recorded_nonce`, identical to the receipt's `nonce`).
    pub nonce: [u8; 16],
    /// Which side committed (the other side's record is absent).
    pub committed_side: CommittedSide,
    /// The committed side's event-log entry id.
    pub committed_event_id: String,
}

impl CrossContextDivergenceMarker {
    /// Build the §9.5.1 canonical signing preimage for this divergence marker.
    ///
    /// Field order (normative): `VarBytes(saga_id)`, `RawBytes16(nonce)`,
    /// `U8(committed_side.tag())`, `VarBytes(committed_event_id)`. The variable-
    /// length `saga_id` and `committed_event_id` are length-prefixed by `VarBytes`,
    /// so no splice ambiguity arises at their boundary.
    ///
    /// # Errors
    ///
    /// Returns [`CrossContextSagaError::PreimageConstruction`] only if a
    /// variable-length field exceeds `u32::MAX` bytes (unreachable in practice).
    pub fn signing_preimage(&self) -> Result<[u8; 32], CrossContextSagaError> {
        canonical_hash(
            XCTX_DIVERGENCE_DOMAIN,
            &[
                CanonicalField::VarBytes(self.saga_id.as_bytes()),
                CanonicalField::RawBytes(&self.nonce),
                CanonicalField::U8(self.committed_side.tag()),
                CanonicalField::VarBytes(self.committed_event_id.as_bytes()),
            ],
        )
        .map_err(|e| CrossContextSagaError::PreimageConstruction(e.to_string()))
    }

    /// Sign a divergence marker with the emitting side's Ed25519 signing key.
    ///
    /// # Errors
    ///
    /// Returns [`CrossContextSagaError::PreimageConstruction`] if the preimage
    /// cannot be built (unreachable in practice).
    pub fn sign(
        signing_key: &SigningKey,
        fields: CrossContextDivergenceMarkerFields,
    ) -> Result<Self, CrossContextSagaError> {
        let CrossContextDivergenceMarkerFields {
            saga_id,
            nonce,
            committed_side,
            committed_event_id,
        } = fields;
        let mut marker = Self {
            saga_id,
            nonce,
            committed_side,
            committed_event_id,
            signature: [0u8; 64],
        };
        let preimage = marker.signing_preimage()?;
        marker.signature = signing_key.sign_prehashed_preimage(&preimage);
        Ok(marker)
    }

    /// Verify a divergence marker against the emitting side's authorized signing key.
    ///
    /// As with [`CrossContextOutletReceipt::verify`], the caller MUST resolve and
    /// pass the signing key authorized for the side that emitted the marker; this
    /// function does not trust the marker to name its own authorizing key.
    ///
    /// # Errors
    ///
    /// - [`CrossContextSagaError::PreimageConstruction`] if the preimage cannot
    ///   be built (unreachable in practice).
    /// - [`CrossContextSagaError::SignatureInvalid`] if the signature does not
    ///   verify.
    pub fn verify(
        &self,
        authorized_signing_key: &VerifyingKey,
    ) -> Result<(), CrossContextSagaError> {
        let preimage = self.signing_preimage()?;
        let signature = Signature::from_bytes(&self.signature);
        authorized_signing_key
            .verify_strict(&preimage, &signature)
            .map_err(|e| CrossContextSagaError::SignatureInvalid(e.to_string()))
    }
}

/// Internal helper trait: sign a 32-byte canonical preimage with Ed25519.
///
/// The protocol's canonical construction already hashes the field set into a
/// 32-byte digest (§9.5.1); Ed25519 then signs that digest as its message (the
/// same pattern as the broadcast envelope, which signs the `[u8; 32]` returned
/// by `build_broadcast_signing_payload`). Verification mirrors this by calling
/// `verify_strict(&preimage, &sig)`.
trait SignPrehashedPreimage {
    fn sign_prehashed_preimage(&self, preimage: &[u8; 32]) -> [u8; 64];
}

impl SignPrehashedPreimage for SigningKey {
    fn sign_prehashed_preimage(&self, preimage: &[u8; 32]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.sign(preimage).to_bytes()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A fixed, fully-populated receipt for byte-exactness assertions.
    fn fixed_receipt(signing_key: &SigningKey) -> CrossContextOutletReceipt {
        CrossContextOutletReceipt::sign(
            signing_key,
            CrossContextOutletReceiptFields {
                caller_context_id: [0x11; 32],
                target_context_id: [0x22; 32],
                caller_did: "did:example:caller".to_owned(),
                nonce: [0x33; 16],
                outlet_registration_id: "calc.add".to_owned(),
                output_jcs: br#"{"result":42}"#.to_vec(),
                outlet_invoked_event_id: "evt-outlet-invoked-1".to_owned(),
                chain_depth: 3,
                timestamp_ms: 1_709_654_400_000,
            },
        )
        .expect("sign should succeed")
    }

    #[test]
    fn receipt_preimage_is_byte_exact() {
        let sk = test_signing_key(0xAA);
        let receipt = fixed_receipt(&sk);

        // Independently reconstruct the preimage byte-for-byte: domain prefix,
        // then each field in the normative order with length prefixes.
        let output_hash: [u8; 32] = Sha256::digest(br#"{"result":42}"#).into();
        let mut h = Sha256::new();
        h.update(b"SCP-XCTX-RECEIPT-V1:");
        h.update([0x11; 32]); // Fixed32(caller_context_id)
        h.update([0x22; 32]); // Fixed32(target_context_id)
        h.update(18u32.to_be_bytes()); // len("did:example:caller")
        h.update(b"did:example:caller");
        h.update([0x33; 16]); // RawBytes16(nonce) — no length prefix
        h.update(8u32.to_be_bytes()); // len("calc.add")
        h.update(b"calc.add");
        h.update(output_hash); // Fixed32(output_hash)
        h.update(18u32.to_be_bytes()); // len("evt-outlet-invoked-1")
        h.update(b"evt-outlet-invoked-1");
        h.update([3u8]); // U8(chain_depth)
        h.update(1_709_654_400_000u64.to_be_bytes()); // U64(timestamp_ms)
        let expected: [u8; 32] = h.finalize().into();

        assert_eq!(
            receipt.signing_preimage().expect("preimage"),
            expected,
            "receipt preimage must match the normative §6.2.4 field order"
        );
    }

    #[test]
    fn receipt_round_trip_sign_verify() {
        let sk = test_signing_key(0xAA);
        let receipt = fixed_receipt(&sk);
        receipt
            .verify(&sk.verifying_key())
            .expect("valid receipt must verify against the authorized key");
    }

    #[test]
    fn receipt_tamper_each_covered_field_fails_verify() {
        let sk = test_signing_key(0xAA);
        let vk = sk.verifying_key();
        let base = fixed_receipt(&sk);

        // caller_context_id
        let mut t = base.clone();
        t.caller_context_id[0] ^= 0xFF;
        assert!(t.verify(&vk).is_err());

        // target_context_id
        let mut t = base.clone();
        t.target_context_id[0] ^= 0xFF;
        assert!(t.verify(&vk).is_err());

        // caller_did
        let mut t = base.clone();
        t.caller_did.push('x');
        assert!(t.verify(&vk).is_err());

        // nonce
        let mut t = base.clone();
        t.nonce[0] ^= 0xFF;
        assert!(t.verify(&vk).is_err());

        // outlet_registration_id
        let mut t = base.clone();
        t.outlet_registration_id = "calc.sub".to_owned();
        assert!(t.verify(&vk).is_err());

        // output_jcs (changes recomputed output_hash)
        let mut t = base.clone();
        t.output_jcs = br#"{"result":43}"#.to_vec();
        assert!(t.verify(&vk).is_err());

        // outlet_invoked_event_id
        let mut t = base.clone();
        t.outlet_invoked_event_id = "evt-outlet-invoked-2".to_owned();
        assert!(t.verify(&vk).is_err());

        // chain_depth
        let mut t = base.clone();
        t.chain_depth = 4;
        assert!(t.verify(&vk).is_err());

        // timestamp_ms (consumes `base` — last tamper case in this test)
        let mut t = base;
        t.timestamp_ms += 1;
        assert!(t.verify(&vk).is_err());
    }

    #[test]
    fn receipt_valid_signature_wrong_signer_fails_authorization() {
        // A receipt validly signed by one key must fail when verified against a
        // DIFFERENT key — the signer-authorization input is what binds the receipt
        // to the key authorized for target_context_id.
        let signer = test_signing_key(0xAA);
        let receipt = fixed_receipt(&signer);

        let wrong_authorized = test_signing_key(0xBB).verifying_key();
        assert!(
            receipt.verify(&wrong_authorized).is_err(),
            "a valid Ed25519 signature by a non-authorized key must fail verify"
        );
    }

    #[test]
    fn receipt_output_hash_recomputed_from_carried_bytes() {
        let sk = test_signing_key(0xAA);
        let receipt = fixed_receipt(&sk);
        let expected: [u8; 32] = Sha256::digest(&receipt.output_jcs).into();
        assert_eq!(receipt.output_hash(), expected);
    }

    #[test]
    fn receipt_non_jcs_output_bytes_fails_verify() {
        // The signer hashed the JCS-canonical bytes. If the receipt is mutated to
        // carry a non-JCS (e.g. pretty-printed) serialization of the same logical
        // output, the verifier recomputes a divergent output_hash and verify fails.
        let sk = test_signing_key(0xAA);
        let mut receipt = fixed_receipt(&sk);
        // Same logical value, non-canonical spacing — different bytes, different hash.
        receipt.output_jcs = br#"{ "result": 42 }"#.to_vec();
        assert!(
            receipt.verify(&sk.verifying_key()).is_err(),
            "non-JCS output bytes must diverge on recompute and fail verify"
        );
    }

    #[test]
    fn receipt_splice_resistance_outlet_registration_id_boundary() {
        // Two receipts differing only in where the caller_did / outlet_registration_id
        // boundary falls must produce different preimages — length-prefixing prevents
        // splice ambiguity that raw concatenation would admit.
        let sk = test_signing_key(0xAA);

        let a = CrossContextOutletReceipt::sign(
            &sk,
            CrossContextOutletReceiptFields {
                caller_context_id: [0x11; 32],
                target_context_id: [0x22; 32],
                caller_did: "did:example:ab".to_owned(),
                nonce: [0x33; 16],
                outlet_registration_id: "coutlet".to_owned(),
                output_jcs: b"{}".to_vec(),
                outlet_invoked_event_id: "evt".to_owned(),
                chain_depth: 1,
                timestamp_ms: 1,
            },
        )
        .expect("sign a");
        let b = CrossContextOutletReceipt::sign(
            &sk,
            CrossContextOutletReceiptFields {
                caller_context_id: [0x11; 32],
                target_context_id: [0x22; 32],
                caller_did: "did:example:a".to_owned(),
                nonce: [0x33; 16],
                outlet_registration_id: "bcoutlet".to_owned(),
                output_jcs: b"{}".to_vec(),
                outlet_invoked_event_id: "evt".to_owned(),
                chain_depth: 1,
                timestamp_ms: 1,
            },
        )
        .expect("sign b");

        assert_ne!(
            a.signing_preimage().expect("a"),
            b.signing_preimage().expect("b"),
            "boundary shift between caller_did and outlet_registration_id must change the preimage"
        );
    }

    #[test]
    fn receipt_splice_resistance_caller_did_event_id_boundary() {
        // Symmetric splice check across the outlet_invoked_event_id VarBytes boundary.
        let sk = test_signing_key(0xAA);

        let a = CrossContextOutletReceipt::sign(
            &sk,
            CrossContextOutletReceiptFields {
                caller_context_id: [0x11; 32],
                target_context_id: [0x22; 32],
                caller_did: "did".to_owned(),
                nonce: [0x33; 16],
                outlet_registration_id: "t".to_owned(),
                output_jcs: b"{}".to_vec(),
                outlet_invoked_event_id: "evtX".to_owned(),
                chain_depth: 1,
                timestamp_ms: 1,
            },
        )
        .expect("sign a");
        let b = CrossContextOutletReceipt::sign(
            &sk,
            CrossContextOutletReceiptFields {
                caller_context_id: [0x11; 32],
                target_context_id: [0x22; 32],
                caller_did: "did".to_owned(),
                nonce: [0x33; 16],
                outlet_registration_id: "t".to_owned(),
                output_jcs: b"{}".to_vec(),
                outlet_invoked_event_id: "evt".to_owned(),
                chain_depth: 1,
                timestamp_ms: 1,
            },
        )
        .expect("sign b");
        // a carries "evtX"; b carries "evt". Distinct VarBytes → distinct preimage.
        assert_ne!(
            a.signing_preimage().expect("a"),
            b.signing_preimage().expect("b")
        );
    }

    #[test]
    fn receipt_serde_round_trip() {
        let sk = test_signing_key(0xAA);
        let receipt = fixed_receipt(&sk);
        let json = serde_json::to_string(&receipt).expect("serialize");
        let back: CrossContextOutletReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, back);
        back.verify(&sk.verifying_key())
            .expect("round-tripped receipt still verifies");
    }

    #[test]
    fn divergence_marker_round_trip_sign_verify() {
        let sk = test_signing_key(0xCC);
        let marker = CrossContextDivergenceMarker::sign(
            &sk,
            CrossContextDivergenceMarkerFields {
                saga_id: "saga-123".to_owned(),
                nonce: [0x44; 16],
                committed_side: CommittedSide::Target,
                committed_event_id: "evt-committed-9".to_owned(),
            },
        )
        .expect("sign");
        marker
            .verify(&sk.verifying_key())
            .expect("valid marker must verify");
    }

    #[test]
    fn divergence_marker_tamper_fails_verify() {
        let sk = test_signing_key(0xCC);
        let vk = sk.verifying_key();
        let base = CrossContextDivergenceMarker::sign(
            &sk,
            CrossContextDivergenceMarkerFields {
                saga_id: "saga-123".to_owned(),
                nonce: [0x44; 16],
                committed_side: CommittedSide::Target,
                committed_event_id: "evt-committed-9".to_owned(),
            },
        )
        .expect("sign");

        let mut t = base.clone();
        t.saga_id = "saga-124".to_owned();
        assert!(t.verify(&vk).is_err());

        let mut t = base.clone();
        t.nonce[0] ^= 0xFF;
        assert!(t.verify(&vk).is_err());

        // committed_side flip must invalidate (the tag is bound into the preimage).
        let mut t = base.clone();
        t.committed_side = CommittedSide::Caller;
        assert!(t.verify(&vk).is_err());

        // committed_event_id (consumes `base` — last tamper case in this test)
        let mut t = base;
        t.committed_event_id = "evt-committed-8".to_owned();
        assert!(t.verify(&vk).is_err());
    }

    #[test]
    fn divergence_marker_wrong_signer_fails() {
        let sk = test_signing_key(0xCC);
        let marker = CrossContextDivergenceMarker::sign(
            &sk,
            CrossContextDivergenceMarkerFields {
                saga_id: "saga-123".to_owned(),
                nonce: [0x44; 16],
                committed_side: CommittedSide::Caller,
                committed_event_id: "evt".to_owned(),
            },
        )
        .expect("sign");
        let wrong = test_signing_key(0xDD).verifying_key();
        assert!(marker.verify(&wrong).is_err());
    }

    #[test]
    fn divergence_marker_preimage_is_byte_exact() {
        let sk = test_signing_key(0xCC);
        let marker = CrossContextDivergenceMarker::sign(
            &sk,
            CrossContextDivergenceMarkerFields {
                saga_id: "saga-123".to_owned(),
                nonce: [0x44; 16],
                committed_side: CommittedSide::Target,
                committed_event_id: "evt-committed-9".to_owned(),
            },
        )
        .expect("sign");

        let mut h = Sha256::new();
        h.update(b"SCP-XCTX-DIVERGENCE-V1:");
        h.update(8u32.to_be_bytes()); // len("saga-123")
        h.update(b"saga-123");
        h.update([0x44; 16]); // RawBytes16(nonce)
        h.update([1u8]); // U8(CommittedSide::Target.tag())
        h.update(15u32.to_be_bytes()); // len("evt-committed-9")
        h.update(b"evt-committed-9");
        let expected: [u8; 32] = h.finalize().into();

        assert_eq!(marker.signing_preimage().expect("preimage"), expected);
    }

    #[test]
    fn committed_side_tags_are_distinct_and_stable() {
        assert_eq!(CommittedSide::Caller.tag(), 0);
        assert_eq!(CommittedSide::Target.tag(), 1);
    }

    #[test]
    fn domains_are_distinct() {
        assert_ne!(XCTX_RECEIPT_DOMAIN, XCTX_DIVERGENCE_DOMAIN);
    }
}
