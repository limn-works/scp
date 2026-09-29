//! The curve-neutral signer abstraction (ADR-063 build constraint, plan §1.8).
//!
//! [`ScpSigner`] lets protocol code sign without holding raw key material:
//! production paths back it with a `KeyCustody` handle, so no private key
//! crosses a crate or FFI boundary. [`P256SigningKey`] implements it for
//! software keys. In S0 no shipped path calls it yet; the
//! per-crate migration off `&ed25519_dalek::SigningKey` parameters follows in
//! later PRs, and S12 swaps the implementation to P-256.

use core::future::Future;

use crate::p256::{P256SigningKey, sign_prehash_rfc6979};

/// The signature algorithm an [`ScpSigner`] produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SigAlg {
    /// Ed25519 (RFC 8032): `msg` is the message itself, the public key is 32
    /// bytes, and the signature is the 64-byte `R ‖ S`.
    Ed25519,
    /// ECDSA P-256 / SHA-256 (§9.5): `msg` is the 32-byte §9.5.1 canonical
    /// hash (signed as a prehash, never hashed again), the public key is the
    /// 33-byte SEC1 compressed point, and the signature is the 64-byte low-`s`
    /// `r ‖ s`.
    EcdsaP256Sha256,
}

/// Why an [`ScpSigner`] could not produce a signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// The signer is ECDSA P-256 and `msg` was not a 32-byte digest.
    #[error("ECDSA P-256 signer requires a 32-byte digest, got {0} bytes")]
    InvalidDigestLength(usize),
    /// The key behind the signer is gone (destroyed, or its custody handle is
    /// no longer valid).
    #[error("signing key unavailable: {0}")]
    KeyUnavailable(String),
    /// The backend (software, keystore, secure enclave) failed to sign.
    #[error("signing backend failed: {0}")]
    Backend(String),
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

    /// Signs `msg` and returns the 64-byte signature.
    ///
    /// For [`SigAlg::EcdsaP256Sha256`], `msg` is the 32-byte digest.
    ///
    /// # Errors
    ///
    /// [`SignError::InvalidDigestLength`] when a P-256 signer receives other
    /// than 32 bytes; [`SignError::KeyUnavailable`] or [`SignError::Backend`]
    /// when the key's owner cannot sign.
    fn sign(&self, msg: &[u8]) -> impl Future<Output = Result<[u8; 64], SignError>> + Send;
}

/// The software P-256 signer: a locally held [`P256SigningKey`].
///
/// `sign` takes the 32-byte §9.5.1 digest and returns the low-`s` raw
/// signature; any other input length is [`SignError::InvalidDigestLength`].
impl ScpSigner for P256SigningKey {
    fn algorithm(&self) -> SigAlg {
        SigAlg::EcdsaP256Sha256
    }

    fn public_key(&self) -> Vec<u8> {
        Self::public_key(self).to_compressed().to_vec()
    }

    async fn sign(&self, msg: &[u8]) -> Result<[u8; 64], SignError> {
        let digest: &[u8; 32] = msg
            .try_into()
            .map_err(|_| SignError::InvalidDigestLength(msg.len()))?;
        sign_prehash_rfc6979(self, digest).map_err(|e| SignError::Backend(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::p256::{P256PublicKey, verify_prehash_strict};

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

    /// The shipped `P256SigningKey` signer honours the trait contract: the
    /// 33-byte compressed key, strict-verifiable low-`s` signatures that match
    /// the direct RFC 6979 path, and a typed error for a non-digest input.
    #[test]
    fn p256_signing_key_signer_contract() {
        let key = P256SigningKey::from_seed(b"t", &[5u8; 32]).unwrap();
        assert_eq!(ScpSigner::algorithm(&key), SigAlg::EcdsaP256Sha256);
        let encoded = ScpSigner::public_key(&key);
        assert_eq!(encoded.len(), 33);
        let pk = P256PublicKey::from_sec1(&encoded).unwrap();
        assert_eq!(pk, key.public_key());

        let digest = [0x11u8; 32];
        let sig = block_on(ScpSigner::sign(&key, &digest)).unwrap();
        verify_prehash_strict(&pk, &digest, &sig).unwrap();
        assert_eq!(sig, sign_prehash_rfc6979(&key, &digest).unwrap());

        for bad in [&b""[..], &[0u8; 31][..], &[0u8; 33][..], b"not a digest"] {
            assert_eq!(
                block_on(ScpSigner::sign(&key, bad)),
                Err(SignError::InvalidDigestLength(bad.len()))
            );
        }
    }
}
