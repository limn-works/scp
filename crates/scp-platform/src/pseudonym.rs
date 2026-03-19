//! Shared pseudonym secret derivation for all [`KeyCustody`](crate::traits::KeyCustody) backends.
//!
//! CRITICAL PRIVACY REQUIREMENT (§9.10.4A): Using public key bytes as the
//! HMAC key for pseudonym derivation would be a membership enumeration oracle —
//! anyone who knows a member's public key could compute their pseudonym for any
//! `context_id` and check relay subscriptions. The `pseudonym_secret` is derived
//! from private key bytes via HKDF-SHA-256, making it unknowable without the
//! private key.

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Salt for HKDF-SHA-256 pseudonym secret derivation (§9.10.4A).
const PSEUDONYM_SECRET_SALT: &[u8] = b"scp-pseudonym-secret-v1";

/// Derives a `pseudonym_secret` from an Ed25519 private key via HKDF-SHA-256.
///
/// ```text
/// pseudonym_secret = HKDF-SHA256(
///     ikm: ed25519_private_key_bytes,
///     salt: "scp-pseudonym-secret-v1",
///     info: "",
///     len: 32
/// )
/// ```
///
/// All three Rust custody backends (`InMemory`, `File`, `SQLite`) use this function
/// to ensure consistent pseudonym derivation. The derived secret is then used
/// as the HMAC key in `derive_pseudonym` and `derive_rotatable_pseudonym`.
pub fn derive_pseudonym_secret(signing_key: &SigningKey) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(PSEUDONYM_SECRET_SALT), signing_key.as_bytes());
    let mut secret = Zeroizing::new([0u8; 32]);
    // HKDF-Expand with 32-byte output cannot fail (32 <= 255 * HashLen).
    assert!(
        hk.expand(b"", secret.as_mut()).is_ok(),
        "HKDF-Expand with 32-byte output is infallible"
    );
    secret
}
