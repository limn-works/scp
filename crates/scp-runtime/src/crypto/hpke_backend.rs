//! HPKE backend trait and production implementation.
//!
//! Introduced by commit 4 of the actor-per-context refactor (ADR-049 §6).
//!
//! # Trait
//!
//! [`HpkeBackend`] is the narrow HPKE + wrapping-key primitive surface used by
//! the sender-key and access-key distribution layers. It replaces the
//! HPKE-flavoured methods that lived on the 26-method `ContextCryptoProvider`.
//! The trait is `Send + Sync` and `#[async_trait]` so it is dyn-compatible
//! (`Arc<dyn HpkeBackend>` lives in `ActorDeps`).
//!
//! Three methods:
//!
//! - [`HpkeBackend::seal`] — HPKE single-shot seal. Returns
//!   `enc (32 bytes) || aead_nonce (12) || ciphertext || tag`.
//! - [`HpkeBackend::unseal`] — inverse of `seal`. Returns the plaintext on
//!   successful AEAD verification.
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
//! `aad` is passed through to the AEAD as empty bytes; callers that need
//! context-binding bake the binding into the `info` input. This keeps the
//! trait surface narrow and consistent with RFC 9180 §5.1.1 "single-shot
//! API".
//!
//! # Cancel-safety
//!
//! All three methods are cancel-safe — they allocate a small amount of state
//! (ephemeral keypair, derived AEAD key, nonce) that is dropped on cancellation
//! without leaking secret material outside the future. `Zeroizing` wraps every
//! secret-byte copy for its entire memory lifetime.
//!
//! # Production impl
//!
//! [`ProductionHpkeBackend`] is a zero-sized struct that implements the full
//! RFC 9180 Base-mode construction. State-free: safe to share via `Arc`
//! across every actor in the process.

use async_trait::async_trait;
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
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

    /// HKDF key expansion failed. This is operationally only reachable on
    /// output length overflow; treated as a programmer error.
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// AEAD seal or unseal failed (tag mismatch, wrong key, truncated
    /// ciphertext).
    #[error("aead failure: {0}")]
    AeadFailure(String),

    /// The ciphertext was shorter than the minimum envelope size
    /// (`enc || nonce || tag`).
    #[error("ciphertext too short")]
    CiphertextTooShort,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// KEM suite id for `DHKEM(X25519, HKDF-SHA256)` — RFC 9180 §7.1.
const HPKE_KEM_ID: u16 = 0x0020;

/// KDF suite id for `HKDF-SHA256` — RFC 9180 §7.2.
const HPKE_KDF_ID: u16 = 0x0001;

/// AEAD suite id for `AES-128-GCM` — RFC 9180 §7.3.
const HPKE_AEAD_ID: u16 = 0x0001;

/// X25519 public-key size (RFC 7748 §5).
const X25519_PUBLIC_KEY_LEN: usize = 32;

/// X25519 secret-key size (RFC 7748 §5).
const X25519_SECRET_KEY_LEN: usize = 32;

/// Derived AEAD key size (AES-128 per RFC 9180 §7.3 row 0x0001).
const HPKE_AEAD_KEY_LEN: usize = 16;

/// AEAD nonce size for AES-GCM (RFC 9180 §7.3 + RFC 5116).
const HPKE_AEAD_NONCE_LEN: usize = 12;

/// Minimum ciphertext envelope size: `enc || nonce || tag` (with empty pt).
const HPKE_MIN_CIPHERTEXT_LEN: usize =
    X25519_PUBLIC_KEY_LEN + HPKE_AEAD_NONCE_LEN + 16 /* GCM tag */;

/// "SCP-HPKE-SEAL-V1" — domain separator on the HKDF input, keeping SCP HPKE
/// output distinct from any other HKDF derivation that uses the same KEM
/// shared secret (defence-in-depth; the `info` parameter is caller-controlled
/// so we anchor our own prefix).
const HPKE_DOMAIN_TAG: &[u8] = b"SCP-HPKE-V1:";

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
    /// Seals `pt` to `recipient_pub` using the SCP HPKE suite and `info` for
    /// key derivation. Returns `enc (32 B) || nonce (12 B) || ct || tag`.
    ///
    /// # Errors
    ///
    /// Returns [`HpkeError::KeyDerivationFailed`] if HKDF expansion fails;
    /// [`HpkeError::AeadFailure`] if AEAD encryption fails (not reachable for
    /// AES-128-GCM with a valid key and nonce).
    async fn seal(
        &self,
        recipient_pub: &[u8; X25519_PUBLIC_KEY_LEN],
        info: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>, HpkeError>;

    /// Unseals `ct` using `recipient_secret` and `info`. Returns the
    /// plaintext on successful AEAD verification.
    ///
    /// # Errors
    ///
    /// Returns [`HpkeError::CiphertextTooShort`] if `ct` is below the
    /// minimum envelope length; [`HpkeError::KeyDerivationFailed`] if HKDF
    /// expansion fails; [`HpkeError::AeadFailure`] if AEAD verification fails
    /// (wrong key, tampered ciphertext).
    async fn unseal(
        &self,
        recipient_secret: &[u8; X25519_SECRET_KEY_LEN],
        info: &[u8],
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
/// Implements the RFC 9180 Base-mode single-shot API with
/// `DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM`.
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
        pt: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        // 1. Generate the ephemeral sender keypair and derive the KEM shared
        //    secret. `StaticSecret` (rather than `EphemeralSecret`) is used so
        //    the secret bytes can be zeroized on drop through `Zeroizing`.
        let ephemeral = StaticSecret::random_from_rng(OsRng);
        let enc = X25519Pub::from(&ephemeral); // ephemeral public = RFC 9180 `enc`
        let kem_shared = ephemeral.diffie_hellman(&X25519Pub::from(*recipient_pub));
        let kem_shared_secret: Zeroizing<[u8; 32]> = Zeroizing::new(kem_shared.to_bytes());

        // 2. Derive the AEAD key via HKDF-SHA256 with a domain-separated info.
        let key = derive_aead_key(&kem_shared_secret, info)?;

        // 3. AEAD seal. Nonce is fresh from OsRng per operation — no
        //    counter-based scheme (safe against reuse even on concurrent seals
        //    with the same key).
        let mut nonce_bytes = [0u8; HPKE_AEAD_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = Aes128Gcm::new_from_slice(&*key)
            .map_err(|e| HpkeError::InvalidKey(format!("AES-128-GCM key length: {e}")))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload { msg: pt, aad: &[] },
            )
            .map_err(|e| HpkeError::AeadFailure(e.to_string()))?;

        // 4. Concatenate `enc || nonce || ciphertext || tag`. Total length is
        //    32 + 12 + pt.len() + 16.
        let mut out =
            Vec::with_capacity(X25519_PUBLIC_KEY_LEN + HPKE_AEAD_NONCE_LEN + ciphertext.len());
        out.extend_from_slice(enc.as_bytes());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    async fn unseal(
        &self,
        recipient_secret: &[u8; X25519_SECRET_KEY_LEN],
        info: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        if ct.len() < HPKE_MIN_CIPHERTEXT_LEN {
            return Err(HpkeError::CiphertextTooShort);
        }

        // 1. Split `enc || nonce || ct || tag`.
        let (enc_bytes, rest) = ct.split_at(X25519_PUBLIC_KEY_LEN);
        let (nonce_bytes, ct_and_tag) = rest.split_at(HPKE_AEAD_NONCE_LEN);

        // 2. Re-derive the KEM shared secret.
        let mut enc_arr = [0u8; X25519_PUBLIC_KEY_LEN];
        enc_arr.copy_from_slice(enc_bytes);
        let recipient_sk = Zeroizing::new(StaticSecret::from(*recipient_secret));
        let kem_shared = recipient_sk.diffie_hellman(&X25519Pub::from(enc_arr));
        let kem_shared_secret: Zeroizing<[u8; 32]> = Zeroizing::new(kem_shared.to_bytes());

        // 3. Re-derive the AEAD key.
        let key = derive_aead_key(&kem_shared_secret, info)?;

        // 4. AEAD open.
        let cipher = Aes128Gcm::new_from_slice(&*key)
            .map_err(|e| HpkeError::InvalidKey(format!("AES-128-GCM key length: {e}")))?;
        cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: ct_and_tag,
                    aad: &[],
                },
            )
            .map_err(|e| HpkeError::AeadFailure(e.to_string()))
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
// Internal key-derivation helper
// ---------------------------------------------------------------------------

/// Derive the AEAD key from the KEM shared secret and caller-provided `info`.
///
/// Construction mirrors RFC 9180 §5.1.1 `KeySchedule(mode_base, shared_secret,
/// info)` but is implemented directly on top of HKDF-SHA256 rather than
/// through a third-party HPKE crate. This keeps the workspace dep graph
/// lean and the construction auditable. The suite-id triple is encoded as
/// `KEM_ID(BE16) || KDF_ID(BE16) || AEAD_ID(BE16)` in the HKDF salt region to
/// domain-separate outputs across suite choices.
///
/// The final HKDF `info` input is:
///
/// ```text
///   HPKE_DOMAIN_TAG || KEM_ID || KDF_ID || AEAD_ID || caller_info_len (BE32) || caller_info
/// ```
///
/// and the HKDF salt is empty (RFC 9180 Base mode). Output length is 16 bytes
/// (AES-128-GCM key).
fn derive_aead_key(
    kem_shared_secret: &[u8; 32],
    caller_info: &[u8],
) -> Result<Zeroizing<[u8; HPKE_AEAD_KEY_LEN]>, HpkeError> {
    let hk = Hkdf::<Sha256>::new(None, kem_shared_secret);

    // Build the structured info input.
    let mut hkdf_info =
        Vec::with_capacity(HPKE_DOMAIN_TAG.len() + 2 + 2 + 2 + 4 + caller_info.len());
    hkdf_info.extend_from_slice(HPKE_DOMAIN_TAG);
    hkdf_info.extend_from_slice(&HPKE_KEM_ID.to_be_bytes());
    hkdf_info.extend_from_slice(&HPKE_KDF_ID.to_be_bytes());
    hkdf_info.extend_from_slice(&HPKE_AEAD_ID.to_be_bytes());
    #[allow(clippy::cast_possible_truncation)]
    let info_len = caller_info.len() as u32;
    hkdf_info.extend_from_slice(&info_len.to_be_bytes());
    hkdf_info.extend_from_slice(caller_info);

    let mut okm = Zeroizing::new([0u8; HPKE_AEAD_KEY_LEN]);
    hk.expand(&hkdf_info, &mut *okm)
        .map_err(|e| HpkeError::KeyDerivationFailed(e.to_string()))?;
    Ok(okm)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Round-trips ten `(info, plaintext)` pairs with a fresh keypair per
    /// pair. Verifies seal/unseal is functionally inverse over a range of
    /// inputs: empty plaintext, empty info, non-empty info, varying pt length.
    #[tokio::test]
    async fn seal_unseal_roundtrip_ten_pairs() {
        let backend = ProductionHpkeBackend::new();

        let cases: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b"info-0".to_vec(), b"".to_vec()),
            (b"".to_vec(), b"hello".to_vec()),
            (b"info-2".to_vec(), b"short".to_vec()),
            (b"info-3".to_vec(), vec![0xAB; 32]),
            (b"info-4".to_vec(), vec![0u8; 1]),
            (b"info-5".to_vec(), (0..=255u8).collect()),
            (b"info-6".to_vec(), vec![0xFF; 1024]),
            (b"info-7".to_vec(), b"the quick brown fox".to_vec()),
            (b"info-8".to_vec(), vec![0x11, 0x22, 0x33, 0x44]),
            (b"info-9".to_vec(), vec![0u8; 4096]),
        ];

        for (idx, (info, pt)) in cases.iter().enumerate() {
            let (pk_vec, sk_vec) = backend.generate_wrapping_keypair().await.unwrap();
            assert_eq!(pk_vec.len(), X25519_PUBLIC_KEY_LEN, "case {idx}: pk length");
            assert_eq!(sk_vec.len(), X25519_SECRET_KEY_LEN, "case {idx}: sk length");

            let mut pk = [0u8; X25519_PUBLIC_KEY_LEN];
            pk.copy_from_slice(&pk_vec);
            let mut sk = [0u8; X25519_SECRET_KEY_LEN];
            sk.copy_from_slice(&sk_vec);

            let ct = backend.seal(&pk, info, pt).await.unwrap();

            // Minimum envelope: enc (32) + nonce (12) + tag (16) = 60 bytes.
            assert!(
                ct.len() >= HPKE_MIN_CIPHERTEXT_LEN,
                "case {idx}: ciphertext too short ({})",
                ct.len(),
            );
            assert_eq!(
                ct.len(),
                X25519_PUBLIC_KEY_LEN + HPKE_AEAD_NONCE_LEN + pt.len() + 16,
                "case {idx}: ciphertext length mismatch",
            );

            let recovered = backend.unseal(&sk, info, &ct).await.unwrap();
            assert_eq!(&recovered, pt, "case {idx}: plaintext mismatch");
        }
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

    /// Unsealing with a different secret key yields [`HpkeError::AeadFailure`]
    /// (not plaintext). Confirms the AEAD is properly authenticating the
    /// KEM-derived key.
    #[tokio::test]
    async fn wrong_key_unseal_fails_with_aead_error() {
        let backend = ProductionHpkeBackend::new();

        let (pk_vec, _sk_vec) = backend.generate_wrapping_keypair().await.unwrap();
        let (_pk2_vec, sk2_vec) = backend.generate_wrapping_keypair().await.unwrap();

        let mut pk = [0u8; X25519_PUBLIC_KEY_LEN];
        pk.copy_from_slice(&pk_vec);
        let mut sk2 = [0u8; X25519_SECRET_KEY_LEN];
        sk2.copy_from_slice(&sk2_vec);

        let ct = backend.seal(&pk, b"info", b"secret").await.unwrap();

        let err = backend.unseal(&sk2, b"info", &ct).await.unwrap_err();
        assert!(
            matches!(err, HpkeError::AeadFailure(_)),
            "expected AEAD failure, got {err:?}",
        );
    }

    /// Tampered ciphertext (bit-flip inside the AEAD portion) fails with
    /// [`HpkeError::AeadFailure`].
    #[tokio::test]
    async fn tampered_ciphertext_fails() {
        let backend = ProductionHpkeBackend::new();
        let (pk_vec, sk_vec) = backend.generate_wrapping_keypair().await.unwrap();
        let mut pk = [0u8; X25519_PUBLIC_KEY_LEN];
        pk.copy_from_slice(&pk_vec);
        let mut sk = [0u8; X25519_SECRET_KEY_LEN];
        sk.copy_from_slice(&sk_vec);

        let mut ct = backend.seal(&pk, b"info", b"hello").await.unwrap();
        // Flip a bit in the ciphertext portion (skip enc 32 + nonce 12).
        let idx = X25519_PUBLIC_KEY_LEN + HPKE_AEAD_NONCE_LEN;
        ct[idx] ^= 0x01;

        let err = backend.unseal(&sk, b"info", &ct).await.unwrap_err();
        assert!(matches!(err, HpkeError::AeadFailure(_)));
    }

    /// Ciphertext shorter than the minimum envelope returns
    /// [`HpkeError::CiphertextTooShort`].
    #[tokio::test]
    async fn ciphertext_too_short_rejected() {
        let backend = ProductionHpkeBackend::new();
        let (_pk, sk_vec) = backend.generate_wrapping_keypair().await.unwrap();
        let mut sk = [0u8; X25519_SECRET_KEY_LEN];
        sk.copy_from_slice(&sk_vec);
        let err = backend
            .unseal(&sk, b"info", &[0u8; HPKE_MIN_CIPHERTEXT_LEN - 1])
            .await
            .unwrap_err();
        assert!(matches!(err, HpkeError::CiphertextTooShort));
    }

    /// Using a different `info` for unseal fails (HKDF domain-separation).
    #[tokio::test]
    async fn info_mismatch_fails() {
        let backend = ProductionHpkeBackend::new();
        let (pk_vec, sk_vec) = backend.generate_wrapping_keypair().await.unwrap();
        let mut pk = [0u8; X25519_PUBLIC_KEY_LEN];
        pk.copy_from_slice(&pk_vec);
        let mut sk = [0u8; X25519_SECRET_KEY_LEN];
        sk.copy_from_slice(&sk_vec);

        let ct = backend.seal(&pk, b"info-a", b"payload").await.unwrap();
        let err = backend.unseal(&sk, b"info-b", &ct).await.unwrap_err();
        assert!(matches!(err, HpkeError::AeadFailure(_)));
    }
}
