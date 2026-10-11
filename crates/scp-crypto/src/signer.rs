//! The curve-neutral signer abstraction (ADR-063, the curve slice's build
//! constraint; ADR-049 Decision 7a, signing through an erased signer).
//!
//! [`ScpSigner`] is the interface through which SCP code signs without
//! holding raw key material. Every signer signs a 32-byte digest, so the
//! type system rules out a non-digest input. [`DynScpSigner`] is the
//! object-safe form of [`ScpSigner`]: ADR-049 Decision 7a has the runtime
//! carry a signer in actor commands as `Arc<dyn DynScpSigner>`, and a blanket
//! implementation makes every [`ScpSigner`] a [`DynScpSigner`].
//!
//! [`P256SecretKey`] implements [`ScpSigner`] for a software P-256 key held in
//! process. `scp_platform::CustodySigner` implements it over a `KeyCustody`
//! handle and is the production signer. `LocalEd25519Signer` signs with an
//! in-process Ed25519 key and compiles only for tests and the `testing`
//! feature.

use core::future::Future;
use core::pin::Pin;

use crate::custody::CustodyFailure;
use crate::p256::{P256SecretKey, sign_prehash_rfc6979};

/// The signature algorithm an [`ScpSigner`] produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SigAlg {
    /// Ed25519 (RFC 8032): the 32-byte digest is the message RFC 8032 signs,
    /// the public key is 32 bytes, and the signature is the 64-byte `R ‖ S`.
    Ed25519,
    /// ECDSA P-256 / SHA-256 (§9.5): the 32-byte digest is the §9.5.1
    /// canonical hash (signed as a prehash, never hashed again), the public
    /// key is the 33-byte SEC1 compressed point, and the signature is the
    /// 64-byte low-`s` `r ‖ s`.
    EcdsaP256Sha256,
}

/// Why an [`ScpSigner`] could not produce a signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// The key behind the signer is gone (destroyed, or its custody handle is
    /// no longer valid).
    #[error("signing key unavailable: {0}")]
    KeyUnavailable(String),
    /// The backend (software, keystore, secure enclave) failed to sign.
    #[error("signing backend failed: {0}")]
    Backend(String),
    /// The key custody refused to sign. The [`CustodyFailure`] keeps the
    /// custody's failure kind, which decides the error code a bridge reports.
    #[error("custody refused to sign: {0}")]
    Custody(CustodyFailure),
}

/// A signer whose key material stays with its owner.
///
/// Implementations must return exactly the signature form [`SigAlg`] documents
/// for [`ScpSigner::algorithm`], and must fail with a typed [`SignError`]
/// rather than return a placeholder signature.
pub trait ScpSigner: Send + Sync {
    /// The algorithm every signature from this signer uses.
    fn algorithm(&self) -> SigAlg;

    /// The public key, in the encoding [`SigAlg`] documents (32 bytes for
    /// Ed25519, 33-byte compressed SEC1 for P-256).
    fn public_key(&self) -> Vec<u8>;

    /// Signs the 32-byte `digest` and returns the 64-byte signature.
    ///
    /// # Errors
    ///
    /// [`SignError::Custody`] when the key custody refuses or fails;
    /// [`SignError::KeyUnavailable`] or [`SignError::Backend`] when another
    /// key owner cannot sign.
    fn sign(&self, digest: &[u8; 32]) -> impl Future<Output = Result<[u8; 64], SignError>> + Send;
}

/// The boxed future [`DynScpSigner::sign_boxed`] returns.
pub type SignFuture<'a> = Pin<Box<dyn Future<Output = Result<[u8; 64], SignError>> + Send + 'a>>;

/// The object-safe form of [`ScpSigner`], for `Arc<dyn DynScpSigner>`.
///
/// [`ScpSigner::sign`] returns an `impl Future`, which makes [`ScpSigner`]
/// unusable as a trait object. This trait boxes that future by hand, because
/// scp-crypto stays a wasm-safe leaf with no `async-trait` dependency. Every
/// [`ScpSigner`] implements it through the blanket implementation below, so
/// implement [`ScpSigner`], never this trait.
pub trait DynScpSigner: Send + Sync {
    /// [`ScpSigner::algorithm`].
    fn algorithm(&self) -> SigAlg;

    /// [`ScpSigner::public_key`].
    fn public_key(&self) -> Vec<u8>;

    /// [`ScpSigner::sign`], with the future boxed.
    fn sign_boxed<'a>(&'a self, digest: &'a [u8; 32]) -> SignFuture<'a>;
}

impl<T: ScpSigner> DynScpSigner for T {
    fn algorithm(&self) -> SigAlg {
        ScpSigner::algorithm(self)
    }

    fn public_key(&self) -> Vec<u8> {
        ScpSigner::public_key(self)
    }

    fn sign_boxed<'a>(&'a self, digest: &'a [u8; 32]) -> SignFuture<'a> {
        Box::pin(ScpSigner::sign(self, digest))
    }
}

/// The software P-256 signer: a locally held [`P256SecretKey`].
///
/// `sign` takes the 32-byte §9.5.1 digest and returns the low-`s` raw
/// signature.
impl ScpSigner for P256SecretKey {
    fn algorithm(&self) -> SigAlg {
        SigAlg::EcdsaP256Sha256
    }

    fn public_key(&self) -> Vec<u8> {
        Self::public_key(self).to_compressed().to_vec()
    }

    async fn sign(&self, digest: &[u8; 32]) -> Result<[u8; 64], SignError> {
        sign_prehash_rfc6979(self, digest).map_err(|e| SignError::Backend(e.to_string()))
    }
}

/// An Ed25519 signer over an in-process `ed25519_dalek::SigningKey`.
///
/// Tests use it where a raw key stood before ADR-049 Decision 7a. It compiles
/// only under `cfg(test)` and the `testing` feature, so no shipped build holds
/// an in-process signing key behind a signer. Its `Debug` output names the
/// public key and never the private key.
#[cfg(any(test, feature = "testing"))]
pub struct LocalEd25519Signer(ed25519_dalek::SigningKey);

#[cfg(any(test, feature = "testing"))]
impl LocalEd25519Signer {
    /// Wraps `key`.
    #[must_use]
    pub const fn new(key: ed25519_dalek::SigningKey) -> Self {
        Self(key)
    }

    /// Builds the signer whose RFC 8032 secret key is `seed`.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }
}

#[cfg(any(test, feature = "testing"))]
impl core::fmt::Debug for LocalEd25519Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocalEd25519Signer")
            .field("public_key", self.0.verifying_key().as_bytes())
            .finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "testing"))]
impl ScpSigner for LocalEd25519Signer {
    fn algorithm(&self) -> SigAlg {
        SigAlg::Ed25519
    }

    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }

    async fn sign(&self, digest: &[u8; 32]) -> Result<[u8; 64], SignError> {
        use ed25519_dalek::Signer as _;
        Ok(self.0.sign(digest).to_bytes())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::custody::CustodyFailureKind;
    use crate::p256::{P256PublicKey, SeedLabel, verify_prehash_strict};

    fn block_on<F: Future>(f: F) -> F::Output {
        use core::pin::pin;
        use core::task::{Context, Poll, Waker};
        let mut f = pin!(f);
        let mut cx = Context::from_waker(Waker::noop());
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("software signer future must be ready on first poll"),
        }
    }

    /// The software `P256SecretKey` signer honours the trait contract: the
    /// 33-byte compressed key, and strict-verifiable low-`s` signatures that
    /// match the direct RFC 6979 path.
    #[test]
    fn p256_secret_key_signer_contract() {
        let key = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[5u8; 32]);
        assert_eq!(ScpSigner::algorithm(&key), SigAlg::EcdsaP256Sha256);
        let encoded = ScpSigner::public_key(&key);
        assert_eq!(encoded.len(), 33);
        let pk = P256PublicKey::from_sec1(&encoded).unwrap();
        assert_eq!(pk, key.public_key());

        let digest = [0x11u8; 32];
        let sig = block_on(ScpSigner::sign(&key, &digest)).unwrap();
        verify_prehash_strict(&pk, &digest, &sig).unwrap();
        assert_eq!(sig, sign_prehash_rfc6979(&key, &digest).unwrap());
    }

    /// `LocalEd25519Signer` signs the 32-byte digest as the RFC 8032 message,
    /// so its output equals `ed25519_dalek::SigningKey::sign` over the same
    /// bytes, and the signature passes `verify_strict`.
    #[test]
    fn local_ed25519_signer_matches_dalek() {
        use ed25519_dalek::{Signer as _, SigningKey};

        for seed in [[7u8; 32], [0xA5u8; 32]] {
            let dalek = SigningKey::from_bytes(&seed);
            let signer = LocalEd25519Signer::from_seed(&seed);
            assert_eq!(ScpSigner::algorithm(&signer), SigAlg::Ed25519);
            assert_eq!(
                ScpSigner::public_key(&signer),
                dalek.verifying_key().to_bytes().to_vec()
            );
            for digest in [[0u8; 32], [0xFFu8; 32], [0x3Cu8; 32]] {
                let sig = block_on(ScpSigner::sign(&signer, &digest)).unwrap();
                assert_eq!(sig, dalek.sign(&digest).to_bytes());
                dalek
                    .verifying_key()
                    .verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&sig))
                    .unwrap();
            }
        }
        let wrapped = LocalEd25519Signer::new(SigningKey::from_bytes(&[7u8; 32]));
        assert_eq!(
            ScpSigner::public_key(&wrapped),
            ScpSigner::public_key(&LocalEd25519Signer::from_seed(&[7u8; 32]))
        );
    }

    /// `LocalEd25519Signer`'s `Debug` output carries the public key and no
    /// byte sequence of the private key.
    #[test]
    fn local_ed25519_signer_debug_redacts_private_key() {
        let seed = [0xA5u8; 32];
        let signer = LocalEd25519Signer::from_seed(&seed);
        let shown = format!("{signer:?}");
        assert!(!shown.contains(&format!("{seed:?}")), "{shown}");
        assert!(!shown.contains("165, 165, 165"), "{shown}");
        assert!(shown.starts_with("LocalEd25519Signer"), "{shown}");
    }

    /// Through `Box<dyn DynScpSigner>`, the algorithm, public key and
    /// signature equal what the concrete `ScpSigner` returns, for both
    /// algorithms.
    #[test]
    fn dyn_signer_forwards() {
        let digest = [0x42u8; 32];
        let ed = LocalEd25519Signer::from_seed(&[9u8; 32]);
        let p256 = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[9u8; 32]);
        let expected = [
            (
                ScpSigner::algorithm(&ed),
                ScpSigner::public_key(&ed),
                block_on(ScpSigner::sign(&ed, &digest)).unwrap(),
            ),
            (
                ScpSigner::algorithm(&p256),
                ScpSigner::public_key(&p256),
                block_on(ScpSigner::sign(&p256, &digest)).unwrap(),
            ),
        ];
        let erased: [Box<dyn DynScpSigner>; 2] = [Box::new(ed), Box::new(p256)];
        for (signer, (alg, pk, sig)) in erased.iter().zip(expected) {
            assert_eq!(signer.algorithm(), alg);
            assert_eq!(signer.public_key(), pk);
            assert_eq!(block_on(signer.sign_boxed(&digest)).unwrap(), sig);
        }
    }

    /// A signer whose custody refuses every request.
    struct RefusingSigner(CustodyFailureKind);

    impl ScpSigner for RefusingSigner {
        fn algorithm(&self) -> SigAlg {
            SigAlg::Ed25519
        }

        fn public_key(&self) -> Vec<u8> {
            vec![0; 32]
        }

        async fn sign(&self, _digest: &[u8; 32]) -> Result<[u8; 64], SignError> {
            Err(SignError::Custody(CustodyFailure {
                kind: self.0,
                detail: "refused by the test custody".to_owned(),
            }))
        }
    }

    /// `SignError::Custody` carries the custody's failure kind and detail
    /// unchanged through the erased signer, so a caller can map the kind to
    /// its error code.
    #[test]
    fn sign_error_custody_carries_kind() {
        for kind in [
            CustodyFailureKind::KeyNotFound,
            CustodyFailureKind::PseudonymRejected,
            CustodyFailureKind::StorageClosed,
            CustodyFailureKind::StorageLockHeld,
            CustodyFailureKind::Failed,
        ] {
            let signer: Box<dyn DynScpSigner> = Box::new(RefusingSigner(kind));
            let err = block_on(signer.sign_boxed(&[0u8; 32])).unwrap_err();
            let SignError::Custody(failure) = &err else {
                panic!("expected SignError::Custody, got {err:?}");
            };
            assert_eq!(failure.kind, kind);
            assert_eq!(failure.detail, "refused by the test custody");
            assert_eq!(
                err.to_string(),
                "custody refused to sign: key custody failed: refused by the test custody"
            );
        }
    }
}
