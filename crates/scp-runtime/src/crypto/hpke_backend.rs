//! HPKE backend trait and production implementation.
//!
//! Introduced by commit 4 of the actor-per-context refactor (ADR-049 §6).
//!
//! # Trait
//!
//! [`HpkeBackend`] is the narrow HPKE + wrapping-key primitive surface used by
//! the sender-key and access-key distribution layers. It is the ADR-049 §6
//! actor seam (an `Arc<dyn HpkeBackend>` lives in `ActorDeps`). The trait is
//! `Send + Sync` and `#[async_trait]` so it is dyn-compatible.
//!
//! Three methods:
//!
//! - [`HpkeBackend::seal`] — RFC 9180 single-shot Base-mode seal. Returns
//!   `(enc, ct)`: the 32-byte HPKE encapsulated key and the AEAD ciphertext
//!   (`ciphertext || tag`). There is no external nonce — RFC 9180 derives the
//!   AEAD nonce internally (`base_nonce` at sequence 0).
//! - [`HpkeBackend::unseal`] — inverse of `seal` for a software-held recipient
//!   secret.
//! - [`HpkeBackend::generate_wrapping_keypair`] — fresh X25519 keypair.
//!
//! # RFC 9180 parameters
//!
//! - KEM: `DHKEM(X25519, HKDF-SHA256)` (suite id `0x0020`).
//! - KDF: `HKDF-SHA256` (suite id `0x0001`).
//! - AEAD: `AES-128-GCM` (suite id `0x0001`).
//!
//! These match the SCP ciphersuite (spec §9.5 — AES-128-GCM for parity with
//! the MLS ciphersuite's 128-bit security bound).
//!
//! `info` and `aad` are both passed through to the shared HPKE core; callers
//! that need context-binding bake the binding into `info`/`aad` (per §9.16.2 /
//! §9.17.1).
//!
//! # Production impl
//!
//! [`ProductionHpkeBackend`] is a zero-sized struct that delegates to the
//! authoritative RFC 9180 core in [`scp_protocol::crypto::hpke`]. State-free:
//! safe to share via `Arc` across every actor in the process.

use async_trait::async_trait;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use scp_protocol::crypto::hpke;
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by [`HpkeBackend`] operations.
#[derive(Debug, thiserror::Error)]
pub enum HpkeError {
    /// Key material was the wrong length or otherwise unusable.
    #[error("invalid key material: {0}")]
    InvalidKey(String),

    /// HPKE seal failed (operationally unreachable for AES-128-GCM with a
    /// valid key and nonce).
    #[error("HPKE seal failed: {0}")]
    SealFailed(String),

    /// HPKE open failed (tag mismatch, wrong key, wrong `info`/`aad`, tampered
    /// `enc`/`ct`).
    #[error("HPKE open failed: {0}")]
    OpenFailed(String),
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// X25519 public-key size (RFC 7748 §5).
const X25519_PUBLIC_KEY_LEN: usize = 32;

/// X25519 secret-key size (RFC 7748 §5).
const X25519_SECRET_KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// HPKE + wrapping-key primitives used by the sender-key and access-key
/// distribution layers.
///
/// Implementations MUST be stateless and safe to share via `Arc` across
/// actor boundaries. All operations are cancel-safe.
#[async_trait]
pub trait HpkeBackend: Send + Sync {
    /// RFC 9180 single-shot Base-mode seal of `pt` to `recipient_pub` under
    /// `info` and `aad`. Returns `(enc, ct)`: the 32-byte encapsulated key and
    /// the AEAD ciphertext (`ciphertext || tag`).
    ///
    /// # Errors
    ///
    /// Returns [`HpkeError::SealFailed`] if the HPKE seal fails (operationally
    /// unreachable with valid inputs).
    async fn seal(
        &self,
        recipient_pub: &[u8; X25519_PUBLIC_KEY_LEN],
        info: &[u8],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), HpkeError>;

    /// RFC 9180 single-shot Base-mode open of `ct` (with encapsulated key
    /// `enc`) using a software-held `recipient_secret`, under `info`/`aad`.
    /// Returns the plaintext on successful AEAD verification.
    ///
    /// # Errors
    ///
    /// Returns [`HpkeError::InvalidKey`] if `enc` is the wrong length;
    /// [`HpkeError::OpenFailed`] if HPKE open fails (wrong key, wrong
    /// `info`/`aad`, tampered `enc`/`ct`).
    async fn unseal(
        &self,
        recipient_secret: &[u8; X25519_SECRET_KEY_LEN],
        enc: &[u8],
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, HpkeError>;

    /// Generates a fresh X25519 wrapping keypair using `OsRng`.
    /// Returns `(public_key_bytes, secret_key_bytes)`; the secret is wrapped
    /// in [`Zeroizing`] so it zeroes on drop.
    ///
    /// # Errors
    ///
    /// Returns [`HpkeError`] only on construction failures (operationally
    /// unreachable with `OsRng`).
    async fn generate_wrapping_keypair(&self) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HpkeError>;
}

// ---------------------------------------------------------------------------
// Production impl
// ---------------------------------------------------------------------------

/// Production [`HpkeBackend`] implementation.
///
/// Stateless; safe to share via `Arc` across all actors in the process.
/// A thin delegating shim over the authoritative RFC 9180 Base-mode core in
/// [`scp_protocol::crypto::hpke`].
#[derive(Debug, Default, Clone, Copy)]
pub struct ProductionHpkeBackend;

impl ProductionHpkeBackend {
    /// Creates a new production backend.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl HpkeBackend for ProductionHpkeBackend {
    async fn seal(
        &self,
        recipient_pub: &[u8; X25519_PUBLIC_KEY_LEN],
        info: &[u8],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
        let (enc, ct) = hpke::seal(recipient_pub, info, aad, pt)
            .map_err(|e| HpkeError::SealFailed(e.to_string()))?;
        Ok((enc.to_vec(), ct))
    }

    async fn unseal(
        &self,
        recipient_secret: &[u8; X25519_SECRET_KEY_LEN],
        enc: &[u8],
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        let enc_arr: [u8; hpke::HPKE_ENC_LEN] = enc.try_into().map_err(|_| {
            HpkeError::InvalidKey(format!(
                "HPKE enc must be {} bytes, got {}",
                hpke::HPKE_ENC_LEN,
                enc.len()
            ))
        })?;
        hpke::open(recipient_secret, &enc_arr, info, aad, ct)
            .map_err(|e| HpkeError::OpenFailed(e.to_string()))
    }

    async fn generate_wrapping_keypair(&self) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HpkeError> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519Pub::from(&secret);

        let pk_bytes = public.as_bytes().to_vec();
        let sk_bytes = Zeroizing::new(secret.to_bytes().to_vec());
        Ok((pk_bytes, sk_bytes))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Round-trips ten `(info, aad, plaintext)` triples with a fresh keypair
    /// per case. Verifies seal/unseal is functionally inverse over a range of
    /// inputs and that the ciphertext is exactly `pt.len() + 16` (no external
    /// nonce on the wire).
    #[tokio::test]
    async fn seal_unseal_roundtrip_ten_cases() {
        let backend = ProductionHpkeBackend::new();

        let cases: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = vec![
            (b"info-0".to_vec(), b"aad-0".to_vec(), b"hello".to_vec()),
            (b"".to_vec(), b"".to_vec(), b"x".to_vec()),
            (b"info-2".to_vec(), b"".to_vec(), b"short".to_vec()),
            (b"info-3".to_vec(), b"a3".to_vec(), vec![0xAB; 32]),
            (b"info-4".to_vec(), b"a4".to_vec(), vec![0u8; 1]),
            (b"info-5".to_vec(), b"a5".to_vec(), (0..=255u8).collect()),
            (b"info-6".to_vec(), b"a6".to_vec(), vec![0xFF; 1024]),
            (
                b"info-7".to_vec(),
                b"a7".to_vec(),
                b"the quick brown fox".to_vec(),
            ),
            (
                b"info-8".to_vec(),
                b"a8".to_vec(),
                vec![0x11, 0x22, 0x33, 0x44],
            ),
            (b"info-9".to_vec(), b"a9".to_vec(), vec![0u8; 4096]),
        ];

        for (idx, (info, aad, pt)) in cases.iter().enumerate() {
            let (pk_vec, sk_vec) = backend.generate_wrapping_keypair().await.unwrap();
            assert_eq!(pk_vec.len(), X25519_PUBLIC_KEY_LEN, "case {idx}: pk length");
            assert_eq!(sk_vec.len(), X25519_SECRET_KEY_LEN, "case {idx}: sk length");

            let mut pk = [0u8; X25519_PUBLIC_KEY_LEN];
            pk.copy_from_slice(&pk_vec);
            let mut sk = [0u8; X25519_SECRET_KEY_LEN];
            sk.copy_from_slice(&sk_vec);

            let (enc, ct) = backend.seal(&pk, info, aad, pt).await.unwrap();
            assert_eq!(enc.len(), hpke::HPKE_ENC_LEN, "case {idx}: enc length");
            assert_eq!(
                ct.len(),
                pt.len() + hpke::HPKE_TAG_LEN,
                "case {idx}: ct length (no external nonce)",
            );

            let recovered = backend.unseal(&sk, &enc, info, aad, &ct).await.unwrap();
            assert_eq!(&recovered, pt, "case {idx}: plaintext mismatch");
        }
    }

    /// A delegation KAT: a ciphertext produced by the backend opens with the
    /// `scp_protocol::crypto::hpke` core directly (proving the backend is a
    /// faithful shim, not a divergent re-implementation).
    #[tokio::test]
    async fn backend_output_opens_with_core() {
        let backend = ProductionHpkeBackend::new();
        let (pk_vec, sk_vec) = backend.generate_wrapping_keypair().await.unwrap();
        let mut pk = [0u8; X25519_PUBLIC_KEY_LEN];
        pk.copy_from_slice(&pk_vec);
        let mut sk = [0u8; X25519_SECRET_KEY_LEN];
        sk.copy_from_slice(&sk_vec);

        let (enc, ct) = backend
            .seal(&pk, b"info", b"aad", b"payload")
            .await
            .unwrap();
        let enc_arr: [u8; 32] = enc.as_slice().try_into().unwrap();

        let recovered = hpke::open(&sk, &enc_arr, b"info", b"aad", &ct).unwrap();
        assert_eq!(recovered.as_slice(), b"payload");
    }

    /// Generated X25519 keypair has the expected byte shape (32/32) and the
    /// public key equals `X25519(secret, basepoint)`.
    #[tokio::test]
    async fn keypair_has_expected_shape() {
        let backend = ProductionHpkeBackend::new();
        let (pk, sk) = backend.generate_wrapping_keypair().await.unwrap();
        assert_eq!(pk.len(), X25519_PUBLIC_KEY_LEN);
        assert_eq!(sk.len(), X25519_SECRET_KEY_LEN);

        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk);
        let rederived = X25519Pub::from(&StaticSecret::from(sk_arr));
        assert_eq!(rederived.as_bytes().as_slice(), pk.as_slice());
    }

    /// Unsealing with a different secret key yields [`HpkeError::OpenFailed`].
    #[tokio::test]
    async fn wrong_key_unseal_fails() {
        let backend = ProductionHpkeBackend::new();

        let (pk_vec, _sk_vec) = backend.generate_wrapping_keypair().await.unwrap();
        let (_pk2_vec, sk2_vec) = backend.generate_wrapping_keypair().await.unwrap();

        let mut pk = [0u8; X25519_PUBLIC_KEY_LEN];
        pk.copy_from_slice(&pk_vec);
        let mut sk2 = [0u8; X25519_SECRET_KEY_LEN];
        sk2.copy_from_slice(&sk2_vec);

        let (enc, ct) = backend.seal(&pk, b"info", b"aad", b"secret").await.unwrap();

        let err = backend
            .unseal(&sk2, &enc, b"info", b"aad", &ct)
            .await
            .unwrap_err();
        assert!(matches!(err, HpkeError::OpenFailed(_)), "got {err:?}");
    }

    /// Tampered ciphertext fails with [`HpkeError::OpenFailed`].
    #[tokio::test]
    async fn tampered_ciphertext_fails() {
        let backend = ProductionHpkeBackend::new();
        let (pk_vec, sk_vec) = backend.generate_wrapping_keypair().await.unwrap();
        let mut pk = [0u8; X25519_PUBLIC_KEY_LEN];
        pk.copy_from_slice(&pk_vec);
        let mut sk = [0u8; X25519_SECRET_KEY_LEN];
        sk.copy_from_slice(&sk_vec);

        let (enc, mut ct) = backend.seal(&pk, b"info", b"aad", b"hello").await.unwrap();
        ct[0] ^= 0x01;

        let err = backend
            .unseal(&sk, &enc, b"info", b"aad", &ct)
            .await
            .unwrap_err();
        assert!(matches!(err, HpkeError::OpenFailed(_)));
    }

    /// Wrong-length `enc` returns [`HpkeError::InvalidKey`].
    #[tokio::test]
    async fn wrong_length_enc_rejected() {
        let backend = ProductionHpkeBackend::new();
        let (_pk, sk_vec) = backend.generate_wrapping_keypair().await.unwrap();
        let mut sk = [0u8; X25519_SECRET_KEY_LEN];
        sk.copy_from_slice(&sk_vec);
        let err = backend
            .unseal(&sk, &[0u8; 31], b"info", b"aad", &[0u8; 48])
            .await
            .unwrap_err();
        assert!(matches!(err, HpkeError::InvalidKey(_)));
    }

    /// Using a different `info` for unseal fails (HPKE domain-separation).
    #[tokio::test]
    async fn info_mismatch_fails() {
        let backend = ProductionHpkeBackend::new();
        let (pk_vec, sk_vec) = backend.generate_wrapping_keypair().await.unwrap();
        let mut pk = [0u8; X25519_PUBLIC_KEY_LEN];
        pk.copy_from_slice(&pk_vec);
        let mut sk = [0u8; X25519_SECRET_KEY_LEN];
        sk.copy_from_slice(&sk_vec);

        let (enc, ct) = backend
            .seal(&pk, b"info-a", b"aad", b"payload")
            .await
            .unwrap();
        let err = backend
            .unseal(&sk, &enc, b"info-b", b"aad", &ct)
            .await
            .unwrap_err();
        assert!(matches!(err, HpkeError::OpenFailed(_)));
    }

    /// Using a different `aad` for unseal fails.
    #[tokio::test]
    async fn aad_mismatch_fails() {
        let backend = ProductionHpkeBackend::new();
        let (pk_vec, sk_vec) = backend.generate_wrapping_keypair().await.unwrap();
        let mut pk = [0u8; X25519_PUBLIC_KEY_LEN];
        pk.copy_from_slice(&pk_vec);
        let mut sk = [0u8; X25519_SECRET_KEY_LEN];
        sk.copy_from_slice(&sk_vec);

        let (enc, ct) = backend
            .seal(&pk, b"info", b"aad-a", b"payload")
            .await
            .unwrap();
        let err = backend
            .unseal(&sk, &enc, b"info", b"aad-b", &ct)
            .await
            .unwrap_err();
        assert!(matches!(err, HpkeError::OpenFailed(_)));
    }
}
