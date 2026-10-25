//! [`CustodySigner`]: the production [`ScpSigner`], which signs through a
//! [`KeyCustody`] handle (ADR-049 Decision 7a, signing through an erased
//! signer; ADR-063, the curve slice's build constraint).
//!
//! The signer owns an `Arc` of its custody, so a runtime command can carry it
//! across the actor mailbox as `Arc<dyn scp_crypto::DynScpSigner>`. The private
//! key stays inside the custody: the signer holds the handle, the algorithm and
//! the public key, and nothing else.

use std::fmt;
use std::sync::Arc;

use scp_crypto::{CustodyFailure, ScpSigner, SigAlg, SignError};

use crate::error::PlatformError;
use crate::traits::{KeyCustody, KeyHandle, KeyType};

/// An [`ScpSigner`] over one key held by a [`KeyCustody`].
///
/// [`ScpSigner::public_key`] is synchronous and [`KeyCustody::public_key`] is
/// not, so [`CustodySigner::new`] reads the public key once and caches it.
pub struct CustodySigner<C: KeyCustody> {
    custody: Arc<C>,
    handle: KeyHandle,
    alg: SigAlg,
    public_key: Vec<u8>,
}

impl<C: KeyCustody> CustodySigner<C> {
    /// Builds the signer for `handle` in `custody`, signing with `alg`.
    ///
    /// [`KeyCustody`] has no key-type query, so the caller names `alg`, and
    /// this constructor checks it against the length of the public key the
    /// custody reports: 32 bytes for [`SigAlg::Ed25519`], 33 for
    /// [`SigAlg::EcdsaP256Sha256`]. A 65-byte HPKE P-256 key fails both
    /// checks. A key-event key reports the same 33-byte point as a P-256
    /// signing key, so it passes the check for
    /// [`SigAlg::EcdsaP256Sha256`]; every [`ScpSigner::sign`] through it then
    /// fails, because the custody's `sign` refuses a key-event key with
    /// [`PlatformError::WrongKeyType`] (spec 09 §9.7.4.2 R10).
    ///
    /// # Errors
    ///
    /// - [`PlatformError::KeyNotFound`] when `handle` is unknown or its key was
    ///   destroyed, and any other error [`KeyCustody::public_key`] returns.
    /// - [`PlatformError::WrongKeyType`] when the public key's length belongs
    ///   to a key type other than the one `alg` signs with.
    /// - [`PlatformError::CustodyError`] when the public key's length belongs
    ///   to no key type.
    /// - [`PlatformError::Unsupported`] when `alg` is an algorithm this
    ///   signer does not implement.
    pub async fn new(
        custody: Arc<C>,
        handle: KeyHandle,
        alg: SigAlg,
    ) -> Result<Self, PlatformError> {
        let expected = signing_key_type(alg)?;
        let public_key = custody.public_key(&handle).await?.into_bytes();
        if public_key.len() != public_key_len(expected) {
            let actual = key_type_of_len(public_key.len()).ok_or_else(|| {
                PlatformError::CustodyError(format!(
                    "custody reported a {}-byte public key, which matches no key type",
                    public_key.len()
                ))
            })?;
            return Err(PlatformError::WrongKeyType { expected, actual });
        }
        Ok(Self {
            custody,
            handle,
            alg,
            public_key,
        })
    }

    /// The custody handle of the key this signer signs with.
    #[must_use]
    pub const fn handle(&self) -> KeyHandle {
        self.handle
    }
}

/// The custody key type that signs with `alg`.
const fn signing_key_type(alg: SigAlg) -> Result<KeyType, PlatformError> {
    match alg {
        SigAlg::Ed25519 => Ok(KeyType::Ed25519),
        SigAlg::EcdsaP256Sha256 => Ok(KeyType::P256Signing),
        _ => Err(PlatformError::Unsupported(
            "CustodySigner supports only Ed25519 and ECDSA P-256 signing",
        )),
    }
}

/// The length of the public key [`KeyCustody::public_key`] returns for
/// `key_type`.
const fn public_key_len(key_type: KeyType) -> usize {
    match key_type {
        KeyType::Ed25519 => 32,
        KeyType::P256Signing | KeyType::P256KeyEvent => 33,
        KeyType::HpkeP256 => 65,
    }
}

/// The key type a public key of `len` bytes belongs to. A key-event key's
/// 33 bytes read as [`KeyType::P256Signing`], the only type of that length
/// [`signing_key_type`] names.
const fn key_type_of_len(len: usize) -> Option<KeyType> {
    match len {
        32 => Some(KeyType::Ed25519),
        33 => Some(KeyType::P256Signing),
        65 => Some(KeyType::HpkeP256),
        _ => None,
    }
}

impl<C: KeyCustody + 'static> ScpSigner for CustodySigner<C> {
    fn algorithm(&self) -> SigAlg {
        self.alg
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// Signs `digest` through [`KeyCustody::sign`]. A custody error becomes
    /// [`SignError::Custody`] with the kind `CustodyFailure::from` assigns, so
    /// a destroyed key stays key-not-found (`SCP-CRYPTO-4006`).
    async fn sign(&self, digest: &[u8; 32]) -> Result<[u8; 64], SignError> {
        let signature = self
            .custody
            .sign(&self.handle, digest)
            .await
            .map_err(|e| SignError::Custody(CustodyFailure::from(&e)))?
            .into_bytes();
        <[u8; 64]>::try_from(signature.as_slice()).map_err(|_| {
            SignError::Backend(format!(
                "custody returned a {}-byte signature, expected 64",
                signature.len()
            ))
        })
    }
}

/// Shows the handle and the algorithm only.
impl<C: KeyCustody> fmt::Debug for CustodySigner<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustodySigner")
            .field("handle", &self.handle)
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;
    use crate::testing::InMemoryKeyCustody;
    use ed25519_dalek::{Signature, VerifyingKey};
    use scp_crypto::{CustodyFailureKind, LocalEd25519Signer};
    use sha2::{Digest, Sha256};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A `CustodySigner` over an in-memory custody key imported from a seed
    /// signs exactly as `LocalEd25519Signer` over that seed, so moving a
    /// caller from a raw key to custody changes no signed byte.
    #[tokio::test]
    async fn custody_signer_output_equals_local_ed25519_signer() -> TestResult {
        let digests: [[u8; 32]; 3] = [[0; 32], [0xFF; 32], Sha256::digest(b"scp").into()];
        for seed in [[7u8; 32], [0xA5u8; 32]] {
            let custody = Arc::new(InMemoryKeyCustody::new());
            let handle = custody.import_ed25519_key(&seed).await;
            let signer = CustodySigner::new(custody, handle, SigAlg::Ed25519).await?;
            let local = LocalEd25519Signer::from_seed(&seed);
            assert_eq!(signer.handle(), handle);
            assert_eq!(ScpSigner::algorithm(&signer), SigAlg::Ed25519);
            assert_eq!(
                ScpSigner::public_key(&signer),
                ScpSigner::public_key(&local)
            );
            let verifying_key = VerifyingKey::from_bytes(&<[u8; 32]>::try_from(
                ScpSigner::public_key(&signer).as_slice(),
            )?)?;
            for digest in &digests {
                let via_custody = ScpSigner::sign(&signer, digest).await?;
                let via_local = ScpSigner::sign(&local, digest).await?;
                assert_eq!(via_custody, via_local);
                verifying_key.verify_strict(digest, &Signature::from_bytes(&via_custody))?;
            }
        }
        Ok(())
    }

    /// A P-256 custody key signs the digest as a prehash, and the signature
    /// verifies strictly against the cached 33-byte public key.
    #[tokio::test]
    async fn custody_signer_p256_signature_verifies() -> TestResult {
        let custody = Arc::new(InMemoryKeyCustody::from_seed_bytes([3; 32]));
        let handle = custody.generate_keypair(KeyType::P256Signing).await?;
        let signer = CustodySigner::new(custody, handle, SigAlg::EcdsaP256Sha256).await?;
        let public_key = ScpSigner::public_key(&signer);
        assert_eq!(public_key.len(), 33);
        let digest: [u8; 32] = Sha256::digest(b"scp").into();
        let signature = ScpSigner::sign(&signer, &digest).await?;
        let point = scp_crypto::p256::P256PublicKey::from_sec1(&public_key)?;
        scp_crypto::p256::verify_prehash_strict(&point, &digest, &signature)?;
        Ok(())
    }

    /// After the custody destroys the key, a sign fails with
    /// `SignError::Custody` of kind `KeyNotFound`, and building a new signer
    /// for the handle fails with `PlatformError::KeyNotFound`.
    #[tokio::test]
    async fn custody_signer_destroyed_key_is_custody_key_not_found() -> TestResult {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let handle = custody.generate_keypair(KeyType::Ed25519).await?;
        let signer = CustodySigner::new(Arc::clone(&custody), handle, SigAlg::Ed25519).await?;
        custody.destroy_key(&handle).await?;

        let err = ScpSigner::sign(&signer, &[1; 32]).await;
        assert!(
            matches!(
                &err,
                Err(SignError::Custody(failure)) if failure.kind == CustodyFailureKind::KeyNotFound
            ),
            "{err:?}"
        );
        let rebuilt = CustodySigner::new(custody, handle, SigAlg::Ed25519).await;
        assert!(
            matches!(rebuilt, Err(PlatformError::KeyNotFound)),
            "{rebuilt:?}"
        );
        Ok(())
    }

    /// A handle whose public key length belongs to another key type than the
    /// one `alg` signs with fails construction with `WrongKeyType`, naming the
    /// expected type and the type the length belongs to.
    #[tokio::test]
    async fn custody_signer_rejects_alg_key_length_mismatch() -> TestResult {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let cases = [
            (
                KeyType::Ed25519,
                SigAlg::EcdsaP256Sha256,
                KeyType::P256Signing,
                KeyType::Ed25519,
            ),
            (
                KeyType::P256Signing,
                SigAlg::Ed25519,
                KeyType::Ed25519,
                KeyType::P256Signing,
            ),
            (
                KeyType::HpkeP256,
                SigAlg::Ed25519,
                KeyType::Ed25519,
                KeyType::HpkeP256,
            ),
            (
                KeyType::HpkeP256,
                SigAlg::EcdsaP256Sha256,
                KeyType::P256Signing,
                KeyType::HpkeP256,
            ),
        ];
        for (key_type, alg, want_expected, want_actual) in cases {
            let handle = custody.generate_keypair(key_type).await?;
            let result = CustodySigner::new(Arc::clone(&custody), handle, alg).await;
            assert!(
                matches!(
                    result,
                    Err(PlatformError::WrongKeyType { expected, actual })
                        if expected == want_expected && actual == want_actual
                ),
                "{key_type:?} with {alg:?}: {result:?}"
            );
        }
        Ok(())
    }

    /// A key-event key passes construction for ECDSA P-256 (its public key is
    /// the same 33-byte point), and every sign through it fails with
    /// `SignError::Custody`: `CustodySigner` is no path around R10's refusal
    /// of raw signing by a key-event key.
    #[tokio::test]
    async fn custody_signer_over_key_event_key_refuses_every_sign() -> TestResult {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let handle = custody.generate_key_event_keypair().await?;
        let signer = CustodySigner::new(custody, handle, SigAlg::EcdsaP256Sha256).await?;
        let err = ScpSigner::sign(&signer, &[1; 32]).await;
        assert!(matches!(&err, Err(SignError::Custody(_))), "{err:?}");
        Ok(())
    }

    /// The `Debug` output names the handle and the algorithm, and carries
    /// neither the seed nor the public key.
    #[tokio::test]
    async fn custody_signer_debug_has_no_key_material() -> TestResult {
        let seed = [0xA5u8; 32];
        let custody = Arc::new(InMemoryKeyCustody::new());
        let handle = custody.import_ed25519_key(&seed).await;
        let signer = CustodySigner::new(custody, handle, SigAlg::Ed25519).await?;
        let shown = format!("{signer:?}");
        assert_eq!(
            shown,
            format!("CustodySigner {{ handle: {handle:?}, alg: Ed25519, .. }}")
        );
        assert!(!shown.contains(&format!("{seed:?}")), "{shown}");
        assert!(
            !shown.contains(&format!("{:?}", ScpSigner::public_key(&signer))),
            "{shown}"
        );
        Ok(())
    }
}
