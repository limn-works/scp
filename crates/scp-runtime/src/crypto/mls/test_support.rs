//! Test-only minting of attested `KeyPackages` through an [`MlsBackend`], with
//! the attestation signed by a local Ed25519 key in place of custody.
//!
//! Production mints through
//! [`mint_attested_key_package`](super::attestation_signer::mint_attested_key_package),
//! which signs with the owner's custody-backed `#active` key after checking
//! it against the owner's DID document. A test that needs a `KeyPackage` and
//! no resolver mints here. [`GatedSigner`] stands in for a custody whose
//! sign does not answer.

use async_trait::async_trait;
use ed25519_dalek::{Signer as _, SigningKey};
use scp_mls::credential::ScpCredential;
use scp_mls::error::MlsError;

use super::backend::{GeneratedKeyPackage, MlsBackend};

/// Mints an attested `KeyPackage` through any [`MlsBackend`], for tests.
#[async_trait]
pub trait MintAttestedForTest {
    /// Mints a `KeyPackage` for `credential`'s DID (at `#active`) with `wrapping_pubkey` as its
    /// `0xFF01`, its attestation signed by a fresh Ed25519 key.
    async fn mint_attested_for_test(
        &self,
        credential: &ScpCredential,
        wrapping_pubkey: &[u8; 65],
    ) -> Result<GeneratedKeyPackage, MlsError>;

    /// Mints a `KeyPackage` for `credential`'s DID (at `#active`) with `wrapping_pubkey` as its
    /// `0xFF01`, its attestation signed by `identity_key`.
    async fn mint_attested_with_key_for_test(
        &self,
        credential: &ScpCredential,
        wrapping_pubkey: &[u8; 65],
        identity_key: &SigningKey,
    ) -> Result<GeneratedKeyPackage, MlsError>;
}

#[async_trait]
impl<B: MlsBackend + ?Sized> MintAttestedForTest for B {
    async fn mint_attested_for_test(
        &self,
        credential: &ScpCredential,
        wrapping_pubkey: &[u8; 65],
    ) -> Result<GeneratedKeyPackage, MlsError> {
        let identity_key = SigningKey::generate(&mut rand::rngs::OsRng);
        self.mint_attested_with_key_for_test(credential, wrapping_pubkey, &identity_key)
            .await
    }

    async fn mint_attested_with_key_for_test(
        &self,
        credential: &ScpCredential,
        wrapping_pubkey: &[u8; 65],
        identity_key: &SigningKey,
    ) -> Result<GeneratedKeyPackage, MlsError> {
        let owning_did = scp_did::DID(credential.did.clone());
        let draft = self
            .prepare_key_package(&owning_did, wrapping_pubkey)
            .await?;
        let signature = identity_key.sign(&draft.signing_hash()).to_bytes();
        self.finish_key_package(draft, signature, &identity_key.verifying_key())
            .await
    }
}

/// The `#agent` key the test resolvers name for an identity whose `#active`
/// key is `active`: a fixed key derived from it and distinct from it, so a
/// test can sign with the `#agent` key of any fixture identity.
pub(crate) fn test_agent_key(active: &SigningKey) -> SigningKey {
    let mut seed = active.to_bytes();
    for byte in &mut seed {
        *byte ^= 0x5A;
    }
    SigningKey::from_bytes(&seed)
}

/// The resolver every in-crate test uses: each `(did, active)` pair resolves
/// at `#active` to `active`'s key and at `#agent` to [`test_agent_key`]'s,
/// and every other DID to nothing. Returning different keys per role is what
/// lets a test catch a verifier or signer that asks for the wrong role.
pub(crate) fn role_resolver(
    identities: &[(scp_did::DID, SigningKey)],
) -> scp_protocol::context::governance::KeyResolver {
    let table: Vec<(
        scp_did::DID,
        ed25519_dalek::VerifyingKey,
        ed25519_dalek::VerifyingKey,
    )> = identities
        .iter()
        .map(|(did, active)| {
            (
                did.clone(),
                active.verifying_key(),
                test_agent_key(active).verifying_key(),
            )
        })
        .collect();
    std::sync::Arc::new(move |did: &scp_did::DID, kid: scp_did::SigningKeyId| {
        table
            .iter()
            .find(|(d, _, _)| d == did)
            .map(|(_, active, agent)| match kid {
                scp_did::SigningKeyId::Active => *active,
                scp_did::SigningKeyId::Agent => *agent,
            })
    })
}

/// A local Ed25519 signer whose sign waits for a permit, standing in for a
/// custody that does not answer: each sign counts itself in `signs` and takes
/// one permit, and a sign with none left waits until the test adds one.
pub(crate) struct GatedSigner {
    /// The signing key.
    pub(crate) key: SigningKey,
    /// One permit per sign allowed to finish.
    pub(crate) permits: std::sync::Arc<tokio::sync::Semaphore>,
    /// How many signs have started.
    pub(crate) signs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl scp_crypto::ScpSigner for GatedSigner {
    fn algorithm(&self) -> scp_crypto::SigAlg {
        scp_crypto::SigAlg::Ed25519
    }

    fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().to_bytes().to_vec()
    }

    fn sign(
        &self,
        digest: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<[u8; 64], scp_crypto::SignError>> + Send {
        let permits = std::sync::Arc::clone(&self.permits);
        let signs = std::sync::Arc::clone(&self.signs);
        let signature = self.key.sign(digest).to_bytes();
        async move {
            signs.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            permits
                .acquire()
                .await
                .map_err(|e| scp_crypto::SignError::Backend(e.to_string()))?
                .forget();
            Ok(signature)
        }
    }
}
