//! The adder's `KeyPackage`-attestation verifier over the supervisor's
//! [`KeyResolver`] — §9.7.1 verifier checks 1 and 3–13 for an **Add**
//! (CRYPTO-22 S4, Layer B).
//!
//! [`verify_add_attestation`] resolves the attestation signer's current key
//! through the supervisor's [`KeyResolver`] — `document_vm_key_resolver` in
//! production, which reads the DID document's verification method for the
//! credential's `signing_key_id` — and hands that key to the pure, wasm-safe
//! core [`verify_attestation`] for checks 3–13. Every identifier is resolved:
//! there is no DID-prefix carve-out (§9.7.1 "Fail-closed scope").
//!
//! # Where it runs
//!
//! Wired at `Supervisor::invite_member`, which verifies the invitee's
//! `KeyPackage` before it adds the invitee or seals the invitation; check 2 is
//! unmet until SCP-CRYPTO22-005 (open question (a)).
//!
//! # Check 2 is not met here
//!
//! §9.7.1 check 2 requires the resolving document to be no older than
//! [`MAX_ATTESTATION_KEY_RESOLUTION_STALENESS`](scp_mls::MAX_ATTESTATION_KEY_RESOLUTION_STALENESS)
//! (300 s). The [`KeyResolver`] returns a key, not a document with its
//! resolution time, and the production resolver reads through a DID cache
//! that refreshes on a 24-hour cycle. The freshness seam is SCP-CRYPTO22-005
//! and `.docs/prds/keypackage-attestation.json` open question (a). The pure
//! Layer-A seam [`scp_mls::verify_attestation_with_resolution`], which does
//! enforce check 2 over a resolved document, is unchanged.
//!
//! See spec §9.7.1 (checks 1–13, resolution failure policy, fail-closed
//! scope), §9.12 (rotation is revocation), and §9.14 (clock skew).

use scp_clock::Clock;
use scp_did::DID;
use scp_mls::keypackage_attestation::{AttestationVerificationContext, verify_attestation};
use scp_mls::{
    AttestationResolutionVerifyError, AttestationTrigger, KeyPackageAttestation, ScpCredential,
};
use scp_protocol::context::governance::KeyResolver;

/// The Add-path leaf/credential ground-truth for [`verify_add_attestation`].
///
/// It carries the `KeyPackage`'s `init_key` (`kp_init_key`) directly and has
/// **no** `trigger` field, so [`verify_add_attestation`] can verify only an
/// Add: an [`AttestationTrigger::Update`] is unrepresentable here.
///
/// # Why Update is excluded
///
/// §9.7.1's "Resolution failure policy" gives an already-admitted member's
/// **Update** a *last-known-good grace* on a transient resolution outage,
/// whereas an **Add** is strictly fail-closed. This verifier implements only
/// the fail-closed Add policy; routing an Update through it would let a
/// resolver outage hard-reject a legitimate member's Update.
#[derive(Debug, Clone, Copy)]
pub struct AttestationAddGroundTruth<'a> {
    /// The leaf's `ScpCredential`. Its `did` is the signer DID resolved here,
    /// and its `did`/`signing_key_id` are the check-9/10 ground truth; its
    /// `signing_key_id` names the current verification method for check 1.
    pub credential: &'a ScpCredential,
    /// The leaf's actual `signature_key`, a 65-byte uncompressed P-256 point
    /// (check 4).
    pub leaf_signature_key: &'a [u8; 65],
    /// The leaf's actual ratchet-tree `encryption_key`, a 65-byte DHKEM(P-256)
    /// public key (check 5).
    pub leaf_encryption_key: &'a [u8; 65],
    /// The value of the leaf's `scp_wrapping_key` (`0xFF01`) extension, a
    /// 65-byte DHKEM(P-256) public key (check 6).
    pub leaf_wrapping_key: &'a [u8; 65],
    /// The leaf's `Lifetime.not_before` (check 11).
    pub leaf_lifetime_not_before: u64,
    /// The leaf's `Lifetime.not_after` (check 11).
    pub leaf_lifetime_not_after: u64,
    /// The `KeyPackage`'s `init_key` (checks 7–8) — the Add-specific payload
    /// the [`AttestationTrigger::Add`] variant carries. `verify_add_attestation`
    /// constructs that variant from this field internally.
    pub kp_init_key: &'a [u8; 65],
}

/// A typed reason [`verify_add_attestation`] rejected a
/// [`KeyPackageAttestation`] on an Add (§9.7.1 checks 1 and 3–13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestationRuntimeVerifyError {
    /// Check 1, fail-closed: the resolver returned no key for the
    /// credential's DID at its `signing_key_id` — the DID does not resolve,
    /// or its document names no such verification method. There is NO
    /// fallback to a stale or pre-rotation key (§9.7.1 "Resolution failure
    /// policy", Add).
    #[error("attestation signer's current key does not resolve (fail-closed)")]
    ResolutionNotFound,

    /// Checks 3–13: the pure core rejected, against the resolved key. The
    /// error is [`AttestationResolutionVerifyError::Delegated`] wrapping the
    /// pure core's error verbatim.
    #[error(transparent)]
    Verify(#[from] AttestationResolutionVerifyError),
}

/// Verifies an **Add**-path leaf's [`KeyPackageAttestation`] against the key
/// the signer's DID document currently names — §9.7.1 checks 1 and 3–13.
///
/// Check 1 resolves `ground_truth.credential`'s DID at its `signing_key_id`
/// through `key_resolver`; `None` is a fail-closed reject. Check 10 binds the
/// attestation's `signing_key_id` to the credential's, so the key resolved
/// is the key the attestation names. Checks 3–13 run in the pure core
/// [`verify_attestation`] with the resolved key, `now` from `clock`, and the
/// Add trigger built from `ground_truth.kp_init_key`. A rotated-away key
/// fails check 3 (§9.12). Check 2 is not met here; see the module doc.
///
/// The resolver call is synchronous and may block on a network resolution.
///
/// # Errors
///
/// [`AttestationRuntimeVerifyError::ResolutionNotFound`] when the key does
/// not resolve, and [`AttestationRuntimeVerifyError::Verify`] for the first
/// failing check among 3–13.
pub(crate) fn verify_add_attestation(
    key_resolver: &KeyResolver,
    clock: &dyn Clock,
    attestation: &KeyPackageAttestation,
    ground_truth: &AttestationAddGroundTruth<'_>,
) -> Result<(), AttestationRuntimeVerifyError> {
    let credential = ground_truth.credential;
    let resolved = key_resolver(&DID(credential.did.clone()), credential.signing_key_id)
        .ok_or(AttestationRuntimeVerifyError::ResolutionNotFound)?;
    let resolved_bytes = resolved.to_bytes();
    let now = clock.now_secs();
    verify_attestation(
        attestation,
        &AttestationVerificationContext {
            resolved_current_vm_pubkey: &resolved_bytes,
            leaf_signature_key: ground_truth.leaf_signature_key,
            leaf_encryption_key: ground_truth.leaf_encryption_key,
            leaf_wrapping_key: ground_truth.leaf_wrapping_key,
            leaf_credential_did: &credential.did,
            leaf_credential_signing_key_id: credential.signing_key_id,
            leaf_lifetime_not_before: ground_truth.leaf_lifetime_not_before,
            leaf_lifetime_not_after: ground_truth.leaf_lifetime_not_after,
            now,
            trigger: AttestationTrigger::Add {
                kp_init_key: ground_truth.kp_init_key,
            },
        },
    )
    .map_err(|e| {
        AttestationRuntimeVerifyError::Verify(AttestationResolutionVerifyError::Delegated(e))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use rand::rngs::OsRng;
    use scp_did::SigningKeyId;
    use scp_mls::keypackage_attestation::AttestationVerifyError;
    use std::sync::Arc;
    use std::sync::mpsc;

    const ISSUED: u64 = 1_700_000_000;
    const EXPIRES: u64 = 1_700_086_400;
    const NOW: u64 = 1_700_000_100; // inside [ISSUED, EXPIRES]
    const TEST_DID: &str = "did:dht:z6MkRuntimeSeamTest";

    /// A fixed-time clock.
    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn now_secs(&self) -> u64 {
            self.0
        }
        fn now_millis(&self) -> u64 {
            self.0.saturating_mul(1000)
        }
    }

    /// A resolver that maps every `(did, signing_key_id)` to `key` (or to no
    /// key) and sends each call to the returned receiver.
    fn recording_resolver(
        key: Option<VerifyingKey>,
    ) -> (KeyResolver, mpsc::Receiver<(String, SigningKeyId)>) {
        let (seen, calls) = mpsc::channel();
        let resolver: KeyResolver = Arc::new(move |did: &DID, kid: SigningKeyId| {
            // The receiver lives until the test's last assertion.
            let _ = seen.send((did.0.clone(), kid));
            key
        });
        (resolver, calls)
    }

    /// Every resolver call recorded so far.
    fn recorded(calls: &mpsc::Receiver<(String, SigningKeyId)>) -> Vec<(String, SigningKeyId)> {
        calls.try_iter().collect()
    }

    fn fresh_pub() -> [u8; 32] {
        SigningKey::generate(&mut OsRng).verifying_key().to_bytes()
    }

    /// A fresh 65-byte uncompressed P-256 point for a leaf key position.
    fn fresh_leaf() -> [u8; 65] {
        scp_crypto::p256::P256SecretKey::from_seed(
            scp_crypto::p256::SeedLabel::TestVectorKey,
            &fresh_pub(),
        )
        .public_key()
        .to_uncompressed()
    }

    /// A signed attestation, its leaf ground truth, and the signer's key.
    struct Fx {
        att: KeyPackageAttestation,
        credential: ScpCredential,
        leaf_sig: [u8; 65],
        leaf_enc: [u8; 65],
        leaf_wrap: [u8; 65],
        kp_init: [u8; 65],
        signer: VerifyingKey,
    }

    impl Fx {
        fn ground_truth(&self) -> AttestationAddGroundTruth<'_> {
            AttestationAddGroundTruth {
                credential: &self.credential,
                leaf_signature_key: &self.leaf_sig,
                leaf_encryption_key: &self.leaf_enc,
                leaf_wrapping_key: &self.leaf_wrap,
                leaf_lifetime_not_before: ISSUED,
                leaf_lifetime_not_after: EXPIRES,
                kp_init_key: &self.kp_init,
            }
        }
    }

    /// A signed Add fixture whose signer DID is `did`. The credential fields
    /// are set directly, bypassing `ScpCredential::new`'s prefix validation.
    fn add_fixture(did: &str) -> Fx {
        let signer = SigningKey::generate(&mut OsRng);
        let leaf_sig = fresh_leaf();
        let leaf_enc = fresh_leaf();
        let leaf_wrap = fresh_leaf();
        let kp_init = fresh_leaf();
        let mut att = KeyPackageAttestation {
            did: did.to_owned(),
            leaf_signature_key: leaf_sig,
            leaf_encryption_key: leaf_enc,
            init_key: kp_init,
            wrapping_key: leaf_wrap,
            signing_key_id: SigningKeyId::Active,
            issued_at: ISSUED,
            expires_at: EXPIRES,
            signature: [0u8; 64],
        };
        att.signature = signer.sign(&att.signing_hash()).to_bytes();
        let credential = ScpCredential {
            did: did.to_owned(),
            ucan_token: None,
            signing_key_id: SigningKeyId::Active,
        };
        Fx {
            att,
            credential,
            leaf_sig,
            leaf_enc,
            leaf_wrap,
            kp_init,
            signer: signer.verifying_key(),
        }
    }

    // -- Check 1 resolves the credential's DID at its signing_key_id; the
    //    resolved current key passes checks 3–13.

    #[test]
    fn resolve_success_fresh_current_key_ok() {
        let fx = add_fixture(TEST_DID);
        let (resolver, calls) = recording_resolver(Some(fx.signer));

        let result =
            verify_add_attestation(&resolver, &FixedClock(NOW), &fx.att, &fx.ground_truth());

        assert_eq!(result, Ok(()));
        assert_eq!(
            recorded(&calls),
            vec![(TEST_DID.to_owned(), SigningKeyId::Active)],
            "the signer DID must be resolved exactly once, at the credential's signing_key_id"
        );
    }

    // -- Rotation is revocation: the RESOLVED key drives check 3.

    #[test]
    fn resolved_rotated_key_drives_check3_signature_invalid() {
        let fx = add_fixture(TEST_DID);
        let rotated = SigningKey::generate(&mut OsRng).verifying_key();
        let (resolver, _calls) = recording_resolver(Some(rotated));

        let err = verify_add_attestation(&resolver, &FixedClock(NOW), &fx.att, &fx.ground_truth())
            .unwrap_err();

        assert_eq!(
            err,
            AttestationRuntimeVerifyError::Verify(AttestationResolutionVerifyError::Delegated(
                AttestationVerifyError::SignatureInvalid
            )),
            "the resolved (rotated) key must drive check 3"
        );
    }

    // -- Add fails closed when the key does not resolve.

    #[test]
    fn add_resolution_not_found_is_fail_closed_reject() {
        let fx = add_fixture(TEST_DID);
        let (resolver, calls) = recording_resolver(None);

        let err = verify_add_attestation(&resolver, &FixedClock(NOW), &fx.att, &fx.ground_truth())
            .unwrap_err();

        assert_eq!(err, AttestationRuntimeVerifyError::ResolutionNotFound);
        assert_eq!(recorded(&calls).len(), 1);
    }

    // -- No prefix carve-out: did:test:, did:key: and did:web: signers are
    //    resolved, and an unresolved one fails closed.

    #[test]
    fn did_test_and_did_key_are_resolved_like_any_other_identifier() {
        for did in [
            "did:test:carveout",
            "did:key:z6MkCarveout",
            "did:web:example.com",
        ] {
            let fx = add_fixture(did);
            let (resolver, calls) = recording_resolver(None);

            let err =
                verify_add_attestation(&resolver, &FixedClock(NOW), &fx.att, &fx.ground_truth())
                    .unwrap_err();

            assert_eq!(
                err,
                AttestationRuntimeVerifyError::ResolutionNotFound,
                "{did} must be resolved and fail closed when it does not resolve"
            );
            assert_eq!(
                recorded(&calls),
                vec![(did.to_owned(), SigningKeyId::Active)],
                "{did} must be resolved"
            );
        }
    }
}
