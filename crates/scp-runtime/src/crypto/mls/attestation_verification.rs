//! The adder's `KeyPackage`-attestation verifier over the supervisor's
//! [`KeyResolver`]: §9.7.1 verifier checks 1 and 3–13 for an **Add**.
//!
//! [`verify_add_attestation`] first requires both the attestation and the leaf
//! credential to name `#active` (check 1's role rule), then resolves the
//! signer DID's current `#active` key through the supervisor's
//! [`KeyResolver`] (`document_vm_key_resolver` in production, which reads the
//! DID document's verification method), and hands that key to the pure,
//! wasm-safe core [`verify_attestation`] for checks 3–13. The role it resolves
//! is the literal `#active` from the specification, never a role read from the
//! record it checks. Every identifier is resolved: there is no DID-prefix
//! carve-out (§9.7.1 "Fail-closed scope").
//!
//! # Where it runs
//!
//! Wired at `Supervisor::invite_member` through
//! `Supervisor::verify_key_package_attestation`, which verifies the invitee's
//! `KeyPackage` before it adds the invitee or seals the invitation.
//!
//! # Check 2 is not met here
//!
//! §9.7.1 check 2 requires the resolving document's resolution to be fresh under
//! [`MAX_ATTESTATION_KEY_RESOLUTION_STALENESS`](scp_mls::MAX_ATTESTATION_KEY_RESOLUTION_STALENESS)
//! (§9.18.7; `scp_kel::ResolvedState::is_fresh`). The [`KeyResolver`] returns a key, not a document with its
//! resolution time, and the production resolver reads through a DID cache
//! that refreshes on a 24-hour cycle. The freshness seam is SCP-CRYPTO22-005
//! and `.docs/prds/keypackage-attestation.json` open question (a).
//!
//! See spec §9.7.1 (checks 1–13, resolution failure policy, fail-closed
//! scope), §9.12 (rotation is revocation), and §9.14 (clock skew).

use ed25519_dalek::VerifyingKey;
use scp_clock::Clock;
use scp_did::{DID, SigningKeyId};
use scp_mls::keypackage_attestation::{
    AttestationVerificationContext, AttestationVerifyError, KeyPackageLeafFacts,
    require_active_signer, verify_attestation,
};
use scp_mls::{AttestationTrigger, KeyPackageAttestation};
use scp_protocol::context::governance::KeyResolver;

/// A typed reason [`verify_add_attestation`] rejected a
/// [`KeyPackageAttestation`] on an Add (§9.7.1 checks 1 and 3–13).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestationRuntimeVerifyError {
    /// Check 1, fail-closed: the resolver returned no `#active` key for the
    /// leaf credential's DID: the DID does not resolve, or its document names
    /// no such verification method. There is NO fallback to a stale or
    /// pre-rotation key (§9.7.1 "Resolution failure policy", Add).
    #[error("attestation signer's current #active key does not resolve (fail-closed)")]
    ResolutionNotFound,

    /// Check 1, fail-closed: the blocking resolver task panicked or was
    /// cancelled, so no key was resolved.
    #[error("attestation signer's #active key resolution task failed: {0}")]
    ResolverTaskFailed(String),

    /// Check 1's role rule, or checks 3–13 against the resolved key: the pure
    /// core's error verbatim.
    #[error(transparent)]
    Verify(#[from] AttestationVerifyError),
}

/// Resolves `did`'s current `#active` key through `key_resolver` on the
/// blocking pool.
///
/// The resolver is synchronous and may block on a network resolution, so it
/// never runs on an async worker. The role is the literal `#active`: §9.7.1
/// admits no other attester, so no caller passes one.
///
/// # Errors
///
/// The [`tokio::task::JoinError`] when the resolver task panics or is
/// cancelled; `Ok(None)` when the key does not resolve.
pub(crate) async fn resolve_active_key(
    key_resolver: KeyResolver,
    did: DID,
) -> Result<Option<VerifyingKey>, tokio::task::JoinError> {
    tokio::task::spawn_blocking(move || key_resolver(&did, SigningKeyId::Active)).await
}

/// Verifies an **Add**-path leaf's `0xFF03` `attestation` against the key the
/// signer's DID document currently names at `#active`: §9.7.1 checks 1 and
/// 3–13.
///
/// `leaf` is the `KeyPackage`'s parsed leaf, whose credential DID is the
/// signer resolved; `wrapping_key` is its `0xFF01`. Check 1's role rule runs
/// before any resolution: the attestation and the credential must both name
/// `#active`, or the call fails without asking the resolver. Then the
/// credential DID's `#active` key is resolved (`None` is a fail-closed
/// reject), and checks 3–13 run in [`verify_attestation`] with that key, `now`
/// from `clock`, and the Add trigger over `leaf.init_key`. A rotated-away key
/// fails check 3 (§9.12). Check 2 is not met here; see the module doc.
///
/// # Errors
///
/// - [`AttestationRuntimeVerifyError::Verify`] with
///   [`AttestationVerifyError::SignerNotActive`] when either record names a
///   role other than `#active`; the resolver is not called.
/// - [`AttestationRuntimeVerifyError::ResolutionNotFound`] when the key does
///   not resolve, and [`AttestationRuntimeVerifyError::ResolverTaskFailed`]
///   when the resolver task fails.
/// - [`AttestationRuntimeVerifyError::Verify`] for the first failing check
///   among 3–13.
pub(crate) async fn verify_add_attestation(
    key_resolver: KeyResolver,
    clock: &dyn Clock,
    leaf: &KeyPackageLeafFacts,
    wrapping_key: &[u8; 65],
    attestation: &KeyPackageAttestation,
) -> Result<(), AttestationRuntimeVerifyError> {
    require_active_signer(attestation.signing_key_id, leaf.credential.signing_key_id)?;
    let resolved = resolve_active_key(key_resolver, DID(leaf.credential.did.clone()))
        .await
        .map_err(|e| AttestationRuntimeVerifyError::ResolverTaskFailed(e.to_string()))?
        .ok_or(AttestationRuntimeVerifyError::ResolutionNotFound)?;
    let resolved_bytes = resolved.to_bytes();
    verify_attestation(
        attestation,
        &AttestationVerificationContext {
            resolved_current_vm_pubkey: &resolved_bytes,
            leaf_signature_key: &leaf.signature_key,
            leaf_encryption_key: &leaf.encryption_key,
            leaf_wrapping_key: wrapping_key,
            leaf_credential_did: &leaf.credential.did,
            leaf_credential_signing_key_id: leaf.credential.signing_key_id,
            leaf_lifetime_not_before: leaf.not_before,
            leaf_lifetime_not_after: leaf.not_after,
            now: clock.now_secs(),
            trigger: AttestationTrigger::Add {
                kp_init_key: &leaf.init_key,
            },
        },
    )?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use scp_mls::ScpCredential;
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

    /// A resolver that answers `active` at `#active` and `agent` at `#agent`
    /// for every DID, and sends each call to the returned receiver.
    fn recording_resolver(
        active: Option<VerifyingKey>,
        agent: Option<VerifyingKey>,
    ) -> (KeyResolver, mpsc::Receiver<(String, SigningKeyId)>) {
        let (seen, calls) = mpsc::channel();
        let resolver: KeyResolver = Arc::new(move |did: &DID, kid: SigningKeyId| {
            // The receiver lives until the test's last assertion.
            let _ = seen.send((did.0.clone(), kid));
            match kid {
                SigningKeyId::Active => active,
                SigningKeyId::Agent => agent,
            }
        });
        (resolver, calls)
    }

    /// Every resolver call recorded so far.
    fn recorded(calls: &mpsc::Receiver<(String, SigningKeyId)>) -> Vec<(String, SigningKeyId)> {
        calls.try_iter().collect()
    }

    /// A fresh 65-byte uncompressed P-256 point for a leaf key position.
    fn fresh_leaf() -> [u8; 65] {
        scp_crypto::p256::P256SecretKey::from_seed(
            scp_crypto::p256::SeedLabel::TestVectorKey,
            &SigningKey::generate(&mut OsRng).verifying_key().to_bytes(),
        )
        .public_key()
        .to_uncompressed()
    }

    /// A signed attestation, its leaf, and the key that signed it.
    struct Fx {
        att: KeyPackageAttestation,
        leaf: KeyPackageLeafFacts,
        wrapping: [u8; 65],
        signer: VerifyingKey,
    }

    /// A leaf for `did` whose credential names `credential_role`, with an
    /// attestation naming `attestation_role` signed by `key`. The credential
    /// fields are set directly, bypassing `ScpCredential::new`'s prefix
    /// validation.
    fn fixture_with(
        did: &str,
        credential_role: SigningKeyId,
        attestation_role: SigningKeyId,
        key: &SigningKey,
    ) -> Fx {
        let (sig, enc, wrapping, init) = (fresh_leaf(), fresh_leaf(), fresh_leaf(), fresh_leaf());
        let mut att = KeyPackageAttestation {
            did: did.to_owned(),
            leaf_signature_key: sig,
            leaf_encryption_key: enc,
            init_key: init,
            wrapping_key: wrapping,
            signing_key_id: attestation_role,
            issued_at: ISSUED,
            expires_at: EXPIRES,
            signature: [0u8; 64],
        };
        att.signature = key.sign(&att.signing_hash()).to_bytes();
        let leaf = KeyPackageLeafFacts {
            credential: ScpCredential {
                did: did.to_owned(),
                ucan_token: None,
                signing_key_id: credential_role,
            },
            signature_key: sig,
            encryption_key: enc,
            init_key: init,
            wrapping_key: Some(wrapping),
            not_before: ISSUED,
            not_after: EXPIRES,
            attestation: Some(att.clone()),
        };
        Fx {
            att,
            leaf,
            wrapping,
            signer: key.verifying_key(),
        }
    }

    /// An `#active` leaf for `did` attested by a fresh key.
    fn add_fixture(did: &str) -> Fx {
        fixture_with(
            did,
            SigningKeyId::Active,
            SigningKeyId::Active,
            &SigningKey::generate(&mut OsRng),
        )
    }

    async fn verify(fx: &Fx, resolver: KeyResolver) -> Result<(), AttestationRuntimeVerifyError> {
        verify_add_attestation(resolver, &FixedClock(NOW), &fx.leaf, &fx.wrapping, &fx.att).await
    }

    // -- Check 1 resolves the credential's DID at #active; the resolved
    //    current key passes checks 3–13.

    #[tokio::test]
    async fn resolve_success_fresh_current_key_ok() {
        let fx = add_fixture(TEST_DID);
        let (resolver, calls) = recording_resolver(Some(fx.signer), None);

        assert_eq!(verify(&fx, resolver).await, Ok(()));
        assert_eq!(
            recorded(&calls),
            vec![(TEST_DID.to_owned(), SigningKeyId::Active)],
            "the signer DID must be resolved exactly once, at #active"
        );
    }

    // -- Check 1's role rule: an #agent record is refused before any
    //    resolution, whichever of the two records names it.

    #[tokio::test]
    async fn an_agent_role_is_refused_before_the_resolver_runs() {
        let agent = SigningKey::generate(&mut OsRng);
        for (credential_role, attestation_role) in [
            (SigningKeyId::Agent, SigningKeyId::Agent),
            (SigningKeyId::Active, SigningKeyId::Agent),
            (SigningKeyId::Agent, SigningKeyId::Active),
        ] {
            let fx = fixture_with(TEST_DID, credential_role, attestation_role, &agent);
            // The resolver would vouch for the agent key at #agent.
            let (resolver, calls) = recording_resolver(None, Some(agent.verifying_key()));

            assert_eq!(
                verify(&fx, resolver).await,
                Err(AttestationRuntimeVerifyError::Verify(
                    AttestationVerifyError::SignerNotActive
                )),
                "credential {credential_role:?}, attestation {attestation_role:?}"
            );
            assert!(
                recorded(&calls).is_empty(),
                "no key is resolved for a refused role"
            );
        }
    }

    // -- The #agent key signing an attestation that names #active fails:
    //    the verifier resolves #active itself, and the agent key is not it.

    #[tokio::test]
    async fn the_agent_key_cannot_attest_as_active() {
        let active = SigningKey::generate(&mut OsRng);
        let agent = SigningKey::generate(&mut OsRng);
        let fx = fixture_with(TEST_DID, SigningKeyId::Active, SigningKeyId::Active, &agent);
        let (resolver, calls) =
            recording_resolver(Some(active.verifying_key()), Some(agent.verifying_key()));

        assert_eq!(
            verify(&fx, resolver).await,
            Err(AttestationRuntimeVerifyError::Verify(
                AttestationVerifyError::SignatureInvalid
            ))
        );
        assert_eq!(
            recorded(&calls),
            vec![(TEST_DID.to_owned(), SigningKeyId::Active)]
        );
    }

    // -- Rotation is revocation: the RESOLVED key drives check 3.

    #[tokio::test]
    async fn resolved_rotated_key_drives_check3_signature_invalid() {
        let fx = add_fixture(TEST_DID);
        let rotated = SigningKey::generate(&mut OsRng).verifying_key();
        let (resolver, _calls) = recording_resolver(Some(rotated), None);

        assert_eq!(
            verify(&fx, resolver).await,
            Err(AttestationRuntimeVerifyError::Verify(
                AttestationVerifyError::SignatureInvalid
            )),
            "the resolved (rotated) key must drive check 3"
        );
    }

    // -- Add fails closed when the key does not resolve.

    #[tokio::test]
    async fn add_resolution_not_found_is_fail_closed_reject() {
        let fx = add_fixture(TEST_DID);
        let (resolver, calls) = recording_resolver(None, Some(fx.signer));

        assert_eq!(
            verify(&fx, resolver).await,
            Err(AttestationRuntimeVerifyError::ResolutionNotFound)
        );
        assert_eq!(recorded(&calls).len(), 1);
    }

    // -- No prefix carve-out: did:test:, did:key: and did:web: signers are
    //    resolved, and an unresolved one fails closed.

    #[tokio::test]
    async fn did_test_and_did_key_are_resolved_like_any_other_identifier() {
        for did in [
            "did:test:carveout",
            "did:key:z6MkCarveout",
            "did:web:example.com",
        ] {
            let fx = add_fixture(did);
            let (resolver, calls) = recording_resolver(None, None);

            assert_eq!(
                verify(&fx, resolver).await,
                Err(AttestationRuntimeVerifyError::ResolutionNotFound),
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
