//! Mints a `KeyPackage` whose leaf carries a §9.7.1 `KeyPackage` attestation
//! (`0xFF03`) over the keys the leaf actually holds, with one `openmls` build.
//!
//! The attestation binds the leaf `signature_key`, the leaf `encryption_key`,
//! the `KeyPackage` `init_key` and the `0xFF01` `wrapping_key` (§9.5.2), so it
//! must be signed before the leaf exists, and the signature then rides inside
//! the leaf. `openmls` 0.9.0 has no API that takes caller-supplied init or
//! encryption keys, and spec 09 §9.7.1 requires the mint to need no `openmls`
//! change. Minting is therefore two steps:
//!
//! 1. [`prepare_key_package`] draws the two HPKE input keying materials (IKM)
//!    from the operating system, derives both public keys with the RFC 9180
//!    `DeriveKeyPair` that `openmls` itself calls (deterministic in the IKM),
//!    makes the leaf signer, and returns a [`KeyPackageDraft`] holding the
//!    unsigned attestation. It builds nothing.
//! 2. The caller signs [`KeyPackageDraft::signing_hash`] with the identity's
//!    `#active` key, and [`KeyPackageDraft::finish`] verifies that signature
//!    under the attesting key, then builds the `KeyPackage` once under a provider whose random source replays the two IKM values in
//!    the order `openmls` draws them: init key first, then the leaf encryption
//!    key. `finish` then checks that the built leaf holds exactly the keys the
//!    attestation names and fails closed with
//!    [`MlsError::KeyPackageMintNonDeterministic`] otherwise.
//!
//! Nothing writes a private key into provider storage except that one build,
//! and the replay source holds the IKM only for the life of the draft, so no
//! long-lived seed exists (§9.15). [`InMemoryMlsProvider`] keeps its stateless
//! operating-system random source.

use std::sync::atomic::{AtomicUsize, Ordering};

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use scp_clock::Clock;
use scp_did::{DID, SigningKeyId};
use scp_protocol::crypto::hpke::p256::P256Point;
use zeroize::Zeroizing;

use crate::credential::ScpCredential;
use crate::error::MlsError;
use crate::group::SCP_CIPHERSUITE;
use crate::keypackage_attestation::{
    KeyPackageAttestation, leaf_facts, leaf_public_key,
    scp_capabilities_with_context_params_and_attestation,
};
use crate::lifetime::key_package_lifetime;
use crate::provider::{InMemoryMlsProvider, InMemoryMlsStorage};
use crate::wrapping_extension::make_wrapping_key_extension;

/// Length of each HPKE input keying material: the SCP ciphersuite's
/// `hash_length`, which is what `openmls` asks the random source for.
const IKM_LEN: usize = 32;

/// The number of draws one `KeyPackage` build makes: the init key, then the
/// leaf encryption key.
const IKM_DRAWS: usize = 2;

/// Why [`ReplayRand`] refused a draw. Each one means `openmls` asked for
/// randomness the attested mint did not plan for, so the build fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ReplayRandError {
    /// A draw after the init-key and encryption-key draws.
    #[error("replay random source drawn more than twice")]
    Exhausted,
    /// A draw of a length other than the 32-byte IKM.
    #[error("replay random source asked for {0} bytes, expected 32")]
    WrongLength(usize),
    /// A fixed-size array draw, which a `KeyPackage` build never makes.
    #[error("replay random source does not serve array draws")]
    ArrayDraw,
}

/// The random source of the one attested `KeyPackage` build.
///
/// It returns the draft's two IKM values in order, init key first, and
/// refuses every other draw with a [`ReplayRandError`].
pub(crate) struct ReplayRand {
    ikm: Zeroizing<[[u8; IKM_LEN]; IKM_DRAWS]>,
    // The next draw's index. An atomic counter serves the `&self` interface
    // of `OpenMlsRand` without a lock.
    next: AtomicUsize,
}

impl ReplayRand {
    const fn new(ikm: Zeroizing<[[u8; IKM_LEN]; IKM_DRAWS]>) -> Self {
        Self {
            ikm,
            next: AtomicUsize::new(0),
        }
    }
}

impl OpenMlsRand for ReplayRand {
    type Error = ReplayRandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        Err(ReplayRandError::ArrayDraw)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        if len != IKM_LEN {
            return Err(ReplayRandError::WrongLength(len));
        }
        let index = self.next.fetch_add(1, Ordering::SeqCst);
        // `openmls` moves the returned vector into a zeroizing `Secret`.
        self.ikm
            .get(index)
            .map(|ikm| ikm.to_vec())
            .ok_or(ReplayRandError::Exhausted)
    }
}

/// The provider of the one attested `KeyPackage` build: default crypto, the
/// replay random source, and the storage the built bundle is written to.
struct MintProvider<'a> {
    crypto: &'a RustCrypto,
    rand: &'a ReplayRand,
    storage: &'a InMemoryMlsStorage,
}

impl OpenMlsProvider for MintProvider<'_> {
    type CryptoProvider = RustCrypto;
    type RandProvider = ReplayRand;
    type StorageProvider = InMemoryMlsStorage;

    fn storage(&self) -> &Self::StorageProvider {
        self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        self.rand
    }
}

/// A `KeyPackage` that [`prepare_key_package`] planned and that has not been
/// built yet: its keys, its lifetime, its leaf signer, and the unsigned
/// attestation over them.
///
/// It holds the leaf signer and the two IKM values, so it has no `Debug` and
/// no `Clone`. [`KeyPackageDraft::finish`] consumes it.
pub struct KeyPackageDraft {
    credential: ScpCredential,
    wrapping_pubkey: [u8; 65],
    lifetime: Lifetime,
    signer: SignatureKeyPair,
    ikm: Zeroizing<[[u8; IKM_LEN]; IKM_DRAWS]>,
    // Holds the three derived leaf public keys, the wrapping key and the
    // lifetime window; its signature is all zeros until `finish`.
    attestation: KeyPackageAttestation,
}

impl KeyPackageDraft {
    /// The credential the `KeyPackage` will carry. Its `signing_key_id` is
    /// always `#active`, the identity key that must sign [`Self::signing_hash`].
    #[must_use]
    pub const fn credential(&self) -> &ScpCredential {
        &self.credential
    }

    /// The 32-byte hash the identity key signs (§9.5.1, §9.5.2): the
    /// attestation's [`KeyPackageAttestation::signing_hash`].
    #[must_use]
    pub fn signing_hash(&self) -> [u8; 32] {
        self.attestation.signing_hash()
    }

    /// Builds the `KeyPackage` with `signature` in its `0xFF03` attestation.
    ///
    /// The build runs once, under a provider that replays the draft's two IKM
    /// values, with the draft's lifetime and leaf signer. The leaf carries the
    /// `0xFF01` wrapping key and the `0xFF03` attestation and declares
    /// `0xFF01`, `0xFF02` and `0xFF03`, so the `KeyPackage` can join a context
    /// group. Before it builds anything, `finish` verifies `signature` over
    /// [`Self::signing_hash`] under `attesting_key`, the owner's resolved
    /// `#active` key, so no `KeyPackage` with an unverifiable attestation is
    /// built.
    ///
    /// # Errors
    ///
    /// - [`MlsError::KeyPackageAttestationSignatureInvalid`] if `signature`
    ///   does not verify under `attesting_key`. Nothing is built.
    /// - [`MlsError::ExtensionError`] if the leaf extensions cannot be built.
    /// - [`MlsError::CredentialSerializationFailed`] if the credential does not
    ///   serialize.
    /// - [`MlsError::KeyPackageGenerationFailed`] if `openmls` fails the build,
    ///   including when it draws randomness the replay source refuses.
    /// - [`MlsError::KeyPackageMintNonDeterministic`] if the built leaf's
    ///   signature key, encryption key, init key or lifetime differs from the
    ///   attestation's. The bundle and its storage are dropped.
    pub fn finish(
        self,
        signature: [u8; 64],
        attesting_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(KeyPackageBundle, SignatureKeyPair, InMemoryMlsProvider), MlsError> {
        scp_crypto::verify_ed25519_signature(
            attesting_key.as_bytes(),
            &self.attestation.signing_hash(),
            &signature,
        )
        .map_err(|_| MlsError::KeyPackageAttestationSignatureInvalid)?;
        let Self {
            credential,
            wrapping_pubkey,
            lifetime,
            signer,
            ikm,
            mut attestation,
        } = self;
        attestation.signature = signature;

        let extensions = Extensions::<LeafNode>::from_vec(vec![
            make_wrapping_key_extension(&wrapping_pubkey),
            attestation.make_attestation_extension(),
        ])
        .map_err(|e| MlsError::ExtensionError(format!("attested leaf extensions: {e}")))?;
        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(credential.to_bytes()?).into(),
            signature_key: signer.to_public_vec().into(),
        };

        let crypto = RustCrypto::default();
        let rand = ReplayRand::new(ikm);
        let storage = InMemoryMlsStorage::default();
        let provider = MintProvider {
            crypto: &crypto,
            rand: &rand,
            storage: &storage,
        };
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(scp_capabilities_with_context_params_and_attestation())
            .leaf_node_extensions(extensions)
            .key_package_lifetime(lifetime)
            .build(SCP_CIPHERSUITE, &provider, &signer, credential_with_key)
            .map_err(|e| MlsError::KeyPackageGenerationFailed(e.to_string()))?;

        let built = leaf_facts(bundle.key_package())?;
        if built.signature_key != attestation.leaf_signature_key
            || built.encryption_key != attestation.leaf_encryption_key
            || built.init_key != attestation.init_key
            || built.not_before != attestation.issued_at
            || built.not_after != attestation.expires_at
        {
            return Err(MlsError::KeyPackageMintNonDeterministic);
        }

        Ok((bundle, signer, InMemoryMlsProvider::from_storage(storage)))
    }
}

/// Plans an attested `KeyPackage` for `owning_did` without building it.
///
/// The leaf credential names `owning_did` with `signing_key_id = #active`, and
/// so does the attestation: §9.7.1 admits only the `#active` key as a
/// `KeyPackage` attester, so no caller can choose another role. It draws the init-key and encryption-key IKM from the operating system,
/// derives both DHKEM(P-256) public keys from them, makes a fresh ephemeral
/// leaf signer, computes the lifetime once from `clock`, and fills the
/// unsigned attestation with `issued_at = not_before` and
/// `expires_at = not_after` (§9.7.1). Sign [`KeyPackageDraft::signing_hash`]
/// and pass the signature to [`KeyPackageDraft::finish`].
///
/// # Errors
///
/// - [`MlsError::ExtensionError`] if `wrapping_pubkey` is not a valid
///   uncompressed P-256 point.
/// - [`MlsError::CredentialSerializationFailed`] if `owning_did` is longer
///   than a credential admits.
/// - [`MlsError::KeyPackageGenerationFailed`] if the signer cannot be made,
///   the operating-system random source fails, or key derivation fails.
/// - [`MlsError::InvalidSigner`] if the signer's public key is not 65 bytes.
pub fn prepare_key_package(
    owning_did: &DID,
    wrapping_pubkey: &[u8; 65],
    clock: &dyn Clock,
) -> Result<KeyPackageDraft, MlsError> {
    P256Point::try_from(*wrapping_pubkey)
        .map_err(|e| MlsError::ExtensionError(format!("wrapping key: {e}")))?;
    let credential = ScpCredential::new(owning_did.0.clone(), None, SigningKeyId::Active)?;

    let lifetime = key_package_lifetime(clock);
    let signer = SignatureKeyPair::new(SCP_CIPHERSUITE.signature_algorithm())
        .map_err(|e| MlsError::KeyPackageGenerationFailed(format!("signer generation: {e}")))?;

    let mut ikm = Zeroizing::new([[0u8; IKM_LEN]; IKM_DRAWS]);
    for draw in ikm.iter_mut() {
        getrandom::getrandom(draw).map_err(|e| {
            MlsError::KeyPackageGenerationFailed(format!("operating-system random source: {e}"))
        })?;
    }

    let crypto = RustCrypto::default();
    let [init_ikm, encryption_ikm] = &*ikm;
    let init_key = derive_public_key(&crypto, init_ikm)?;
    let encryption_key = derive_public_key(&crypto, encryption_ikm)?;
    let signature_key = leaf_public_key(&signer.to_public_vec()).map_err(|_| {
        MlsError::InvalidSigner(crate::error::SignerDefect::PublicKeyLength(
            signer.to_public_vec().len(),
        ))
    })?;

    let attestation = KeyPackageAttestation {
        did: credential.did.clone(),
        leaf_signature_key: signature_key,
        leaf_encryption_key: encryption_key,
        init_key,
        wrapping_key: *wrapping_pubkey,
        signing_key_id: SigningKeyId::Active,
        issued_at: lifetime.not_before(),
        expires_at: lifetime.not_after(),
        signature: [0; 64],
    };

    Ok(KeyPackageDraft {
        credential,
        wrapping_pubkey: *wrapping_pubkey,
        lifetime,
        signer,
        ikm,
        attestation,
    })
}

/// Derives the DHKEM(P-256) public key `openmls` derives from `ikm`, and drops
/// the private half (a zeroizing `HpkePrivateKey`) at once.
fn derive_public_key(crypto: &RustCrypto, ikm: &[u8; IKM_LEN]) -> Result<[u8; 65], MlsError> {
    let pair = crypto
        .derive_hpke_keypair(SCP_CIPHERSUITE.hpke_config(), ikm)
        .map_err(|e| MlsError::KeyPackageGenerationFailed(format!("HPKE key derivation: {e:?}")))?;
    leaf_public_key(&pair.public)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand::rngs::OsRng;
    use scp_clock::SystemClock;

    use super::*;
    use crate::keypackage_attestation::{
        AttestationTrigger, AttestationVerificationContext, verify_attestation,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn draft() -> Result<KeyPackageDraft, Box<dyn std::error::Error>> {
        let did = DID("did:dht:z6Mkalice".to_owned());
        let wrapping = scp_crypto::p256::testing::uncompressed_point_for(&did.0);
        Ok(prepare_key_package(&did, &wrapping, &SystemClock)?)
    }

    /// Signs `draft` with a fresh identity key and returns the signature and
    /// that key's verifying half.
    fn sign(draft: &KeyPackageDraft) -> ([u8; 64], ed25519_dalek::VerifyingKey) {
        let identity = SigningKey::generate(&mut OsRng);
        (
            identity.sign(&draft.signing_hash()).to_bytes(),
            identity.verifying_key(),
        )
    }

    /// A finished `KeyPackage`'s attestation, signed over the draft's hash,
    /// passes the full §9.7.1 Add-trigger verification against the leaf it
    /// rides in.
    #[test]
    fn attested_key_package_verifies_under_add_trigger() -> TestResult {
        let identity = SigningKey::generate(&mut OsRng);
        let draft = draft()?;
        let signature = identity.sign(&draft.signing_hash()).to_bytes();
        let (bundle, _signer, _provider) = draft.finish(signature, &identity.verifying_key())?;

        let facts = leaf_facts(bundle.key_package())?;
        let attestation = facts.attestation.ok_or("leaf carries no attestation")?;
        let wrapping_key = facts.wrapping_key.ok_or("leaf carries no wrapping key")?;
        verify_attestation(
            &attestation,
            &AttestationVerificationContext {
                resolved_current_vm_pubkey: &identity.verifying_key().to_bytes(),
                leaf_signature_key: &facts.signature_key,
                leaf_encryption_key: &facts.encryption_key,
                leaf_wrapping_key: &wrapping_key,
                leaf_credential_did: &facts.credential.did,
                leaf_credential_signing_key_id: facts.credential.signing_key_id,
                leaf_lifetime_not_before: facts.not_before,
                leaf_lifetime_not_after: facts.not_after,
                now: SystemClock.now_secs(),
                trigger: AttestationTrigger::Add {
                    kp_init_key: &facts.init_key,
                },
            },
        )?;
        Ok(())
    }

    /// The keys `prepare_key_package` derives are the keys the built leaf
    /// holds, and the leaf declares the context-group capabilities.
    #[test]
    fn prepare_keys_equal_finished_leaf_keys() -> TestResult {
        let draft = draft()?;
        let planned = draft.attestation.clone();
        let (signature, attesting_key) = sign(&draft);
        let (bundle, signer, _provider) = draft.finish(signature, &attesting_key)?;

        let facts = leaf_facts(bundle.key_package())?;
        assert_eq!(facts.signature_key, planned.leaf_signature_key);
        assert_eq!(facts.encryption_key, planned.leaf_encryption_key);
        assert_eq!(facts.init_key, planned.init_key);
        assert_eq!(facts.wrapping_key, Some(planned.wrapping_key));
        assert_eq!(
            (facts.not_before, facts.not_after),
            (planned.issued_at, planned.expires_at)
        );
        assert_eq!(signer.to_public_vec(), planned.leaf_signature_key.to_vec());
        assert_ne!(facts.init_key, facts.encryption_key);

        let capabilities = bundle.key_package().leaf_node().capabilities();
        for extension in [
            0xFF01,
            scp_protocol::context::SCP_CONTEXT_EXTENSION_TYPE_ID,
            0xFF03,
        ] {
            assert!(
                capabilities
                    .extensions()
                    .contains(&ExtensionType::Unknown(extension)),
                "leaf does not declare extension {extension:#06x}"
            );
        }
        Ok(())
    }

    /// A draft whose IKM order no longer matches the order `openmls` draws in
    /// builds a leaf whose keys differ from the attestation's, and `finish`
    /// refuses it.
    #[test]
    fn finish_rejects_a_draft_whose_ikm_order_was_swapped() -> TestResult {
        let mut draft = draft()?;
        draft.ikm.swap(0, 1);
        let (signature, attesting_key) = sign(&draft);
        assert!(matches!(
            draft.finish(signature, &attesting_key),
            Err(MlsError::KeyPackageMintNonDeterministic)
        ));
        Ok(())
    }

    /// A signature made by one key and offered with another key as the
    /// attester is refused before anything is built.
    #[test]
    fn finish_rejects_a_signature_that_does_not_verify_under_the_attesting_key() -> TestResult {
        let first = draft()?;
        let (signature, _signing_key) = sign(&first);
        let (_other_signature, other_key) = sign(&first);
        assert!(matches!(
            first.finish(signature, &other_key),
            Err(MlsError::KeyPackageAttestationSignatureInvalid)
        ));
        let second = draft()?;
        let (_signature, attesting_key) = sign(&second);
        assert!(matches!(
            second.finish([0; 64], &attesting_key),
            Err(MlsError::KeyPackageAttestationSignatureInvalid)
        ));
        Ok(())
    }

    /// Every draft names `#active` in both the credential and the
    /// attestation, whatever the caller holds.
    #[test]
    fn prepare_names_the_active_key_in_credential_and_attestation() -> TestResult {
        let draft = draft()?;
        assert_eq!(draft.credential().signing_key_id, SigningKeyId::Active);
        assert_eq!(draft.attestation.signing_key_id, SigningKeyId::Active);
        Ok(())
    }

    /// A leaf key of any length but 65 bytes is a typed error, not a
    /// truncated or padded key.
    #[test]
    fn leaf_public_key_rejects_a_non_65_byte_key() -> TestResult {
        for len in [0, 33, 64, 66] {
            assert!(matches!(
                leaf_public_key(&vec![4; len]),
                Err(MlsError::ExtensionError(_))
            ));
        }
        assert_eq!(leaf_public_key(&[4; 65])?, [4; 65]);
        Ok(())
    }

    #[test]
    fn replay_rand_fails_closed_on_a_third_draw() -> TestResult {
        let rand = ReplayRand::new(Zeroizing::new([[1; IKM_LEN], [2; IKM_LEN]]));
        assert_eq!(rand.random_vec(IKM_LEN)?, vec![1; IKM_LEN]);
        assert_eq!(rand.random_vec(IKM_LEN)?, vec![2; IKM_LEN]);
        assert_eq!(rand.random_vec(IKM_LEN), Err(ReplayRandError::Exhausted));
        assert_eq!(
            rand.random_array::<IKM_LEN>(),
            Err(ReplayRandError::ArrayDraw)
        );
        Ok(())
    }

    #[test]
    fn replay_rand_rejects_a_non_32_byte_draw() -> TestResult {
        let rand = ReplayRand::new(Zeroizing::new([[1; IKM_LEN], [2; IKM_LEN]]));
        assert_eq!(rand.random_vec(16), Err(ReplayRandError::WrongLength(16)));
        assert_eq!(rand.random_vec(64), Err(ReplayRandError::WrongLength(64)));
        // A refused length consumes no IKM.
        assert_eq!(rand.random_vec(IKM_LEN)?, vec![1; IKM_LEN]);
        Ok(())
    }
}
